rule TTP_XOR_WriteProcessMemory_2a36 {
  strings:
    $key_2a36 = { 7d 44 [2] 4f 66 [2] 49 53 [2] 67 53 [2] 58 4f }

  condition:
    any of them
}