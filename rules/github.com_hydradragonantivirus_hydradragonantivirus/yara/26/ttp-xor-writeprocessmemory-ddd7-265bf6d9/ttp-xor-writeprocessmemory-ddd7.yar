rule TTP_XOR_WriteProcessMemory_ddd7 {
  strings:
    $key_ddd7 = { 8a a5 [2] b8 87 [2] be b2 [2] 90 b2 [2] af ae }

  condition:
    any of them
}