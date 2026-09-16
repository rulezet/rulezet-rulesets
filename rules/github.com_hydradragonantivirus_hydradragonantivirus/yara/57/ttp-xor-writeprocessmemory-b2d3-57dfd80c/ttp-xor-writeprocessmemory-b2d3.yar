rule TTP_XOR_WriteProcessMemory_b2d3 {
  strings:
    $key_b2d3 = { e5 a1 [2] d7 83 [2] d1 b6 [2] ff b6 [2] c0 aa }

  condition:
    any of them
}