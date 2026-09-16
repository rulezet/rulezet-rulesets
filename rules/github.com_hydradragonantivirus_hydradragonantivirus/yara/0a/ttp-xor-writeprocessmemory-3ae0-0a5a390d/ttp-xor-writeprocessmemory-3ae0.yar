rule TTP_XOR_WriteProcessMemory_3ae0 {
  strings:
    $key_3ae0 = { 6d 92 [2] 5f b0 [2] 59 85 [2] 77 85 [2] 48 99 }

  condition:
    any of them
}