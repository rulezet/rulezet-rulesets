rule TTP_XOR_WriteProcessMemory_0843 {
  strings:
    $key_0843 = { 5f 31 [2] 6d 13 [2] 6b 26 [2] 45 26 [2] 7a 3a }

  condition:
    any of them
}