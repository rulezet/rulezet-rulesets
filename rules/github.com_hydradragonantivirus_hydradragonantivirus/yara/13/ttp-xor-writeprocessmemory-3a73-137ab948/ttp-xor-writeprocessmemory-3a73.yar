rule TTP_XOR_WriteProcessMemory_3a73 {
  strings:
    $key_3a73 = { 6d 01 [2] 5f 23 [2] 59 16 [2] 77 16 [2] 48 0a }

  condition:
    any of them
}