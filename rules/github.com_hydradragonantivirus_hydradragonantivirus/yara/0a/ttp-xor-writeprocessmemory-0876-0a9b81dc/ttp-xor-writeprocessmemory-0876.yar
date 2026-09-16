rule TTP_XOR_WriteProcessMemory_0876 {
  strings:
    $key_0876 = { 5f 04 [2] 6d 26 [2] 6b 13 [2] 45 13 [2] 7a 0f }

  condition:
    any of them
}