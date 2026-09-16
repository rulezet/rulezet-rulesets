rule TTP_XOR_WriteProcessMemory_3a16 {
  strings:
    $key_3a16 = { 6d 64 [2] 5f 46 [2] 59 73 [2] 77 73 [2] 48 6f }

  condition:
    any of them
}