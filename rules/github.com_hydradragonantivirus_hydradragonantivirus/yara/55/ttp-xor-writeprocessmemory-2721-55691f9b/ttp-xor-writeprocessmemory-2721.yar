rule TTP_XOR_WriteProcessMemory_2721 {
  strings:
    $key_2721 = { 70 53 [2] 42 71 [2] 44 44 [2] 6a 44 [2] 55 58 }

  condition:
    any of them
}