rule TTP_XOR_WriteProcessMemory_b4d3 {
  strings:
    $key_b4d3 = { e3 a1 [2] d1 83 [2] d7 b6 [2] f9 b6 [2] c6 aa }

  condition:
    any of them
}