rule TTP_XOR_WriteProcessMemory_0336 {
  strings:
    $key_0336 = { 54 44 [2] 66 66 [2] 60 53 [2] 4e 53 [2] 71 4f }

  condition:
    any of them
}