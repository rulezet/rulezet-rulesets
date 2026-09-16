rule TTP_XOR_WriteProcessMemory_1826 {
  strings:
    $key_1826 = { 4f 54 [2] 7d 76 [2] 7b 43 [2] 55 43 [2] 6a 5f }

  condition:
    any of them
}