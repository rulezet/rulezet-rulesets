rule TTP_XOR_WriteProcessMemory_a9d6 {
  strings:
    $key_a9d6 = { fe a4 [2] cc 86 [2] ca b3 [2] e4 b3 [2] db af }

  condition:
    any of them
}