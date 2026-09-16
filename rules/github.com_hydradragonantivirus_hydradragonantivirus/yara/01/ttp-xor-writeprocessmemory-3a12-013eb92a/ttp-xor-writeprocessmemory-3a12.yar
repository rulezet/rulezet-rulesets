rule TTP_XOR_WriteProcessMemory_3a12 {
  strings:
    $key_3a12 = { 6d 60 [2] 5f 42 [2] 59 77 [2] 77 77 [2] 48 6b }

  condition:
    any of them
}