rule TTP_XOR_WriteProcessMemory_0f43 {
  strings:
    $key_0f43 = { 58 31 [2] 6a 13 [2] 6c 26 [2] 42 26 [2] 7d 3a }

  condition:
    any of them
}