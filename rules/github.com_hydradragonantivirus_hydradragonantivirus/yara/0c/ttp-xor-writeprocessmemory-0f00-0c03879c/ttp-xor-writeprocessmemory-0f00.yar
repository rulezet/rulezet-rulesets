rule TTP_XOR_WriteProcessMemory_0f00 {
  strings:
    $key_0f00 = { 58 72 [2] 6a 50 [2] 6c 65 [2] 42 65 [2] 7d 79 }

  condition:
    any of them
}