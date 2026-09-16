rule TTP_XOR_WriteProcessMemory_3a76 {
  strings:
    $key_3a76 = { 6d 04 [2] 5f 26 [2] 59 13 [2] 77 13 [2] 48 0f }

  condition:
    any of them
}