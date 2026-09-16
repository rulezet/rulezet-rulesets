rule TTP_XOR_WriteProcessMemory_1e26 {
  strings:
    $key_1e26 = { 49 54 [2] 7b 76 [2] 7d 43 [2] 53 43 [2] 6c 5f }

  condition:
    any of them
}