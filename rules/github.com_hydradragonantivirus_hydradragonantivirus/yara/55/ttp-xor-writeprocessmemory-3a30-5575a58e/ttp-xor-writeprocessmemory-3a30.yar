rule TTP_XOR_WriteProcessMemory_3a30 {
  strings:
    $key_3a30 = { 6d 42 [2] 5f 60 [2] 59 55 [2] 77 55 [2] 48 49 }

  condition:
    any of them
}