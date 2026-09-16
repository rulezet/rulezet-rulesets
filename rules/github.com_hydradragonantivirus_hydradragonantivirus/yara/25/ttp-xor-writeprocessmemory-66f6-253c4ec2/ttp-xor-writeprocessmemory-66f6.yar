rule TTP_XOR_WriteProcessMemory_66f6 {
  strings:
    $key_66f6 = { 31 84 [2] 03 a6 [2] 05 93 [2] 2b 93 [2] 14 8f }

  condition:
    any of them
}