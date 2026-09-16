rule TTP_XOR_WriteProcessMemory_3a59 {
  strings:
    $key_3a59 = { 6d 2b [2] 5f 09 [2] 59 3c [2] 77 3c [2] 48 20 }

  condition:
    any of them
}