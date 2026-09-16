rule TTP_XOR_WriteProcessMemory_b5d3 {
  strings:
    $key_b5d3 = { e2 a1 [2] d0 83 [2] d6 b6 [2] f8 b6 [2] c7 aa }

  condition:
    any of them
}