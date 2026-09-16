rule TTP_XOR_WriteProcessMemory_4385 {
  strings:
    $key_4385 = { 14 f7 [2] 26 d5 [2] 20 e0 [2] 0e e0 [2] 31 fc }

  condition:
    any of them
}