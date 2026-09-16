rule TTP_XOR_WriteProcessMemory_3376 {
  strings:
    $key_3376 = { 64 04 [2] 56 26 [2] 50 13 [2] 7e 13 [2] 41 0f }

  condition:
    any of them
}