rule TTP_XOR_WriteProcessMemory_6946 {
  strings:
    $key_6946 = { 3e 34 [2] 0c 16 [2] 0a 23 [2] 24 23 [2] 1b 3f }

  condition:
    any of them
}