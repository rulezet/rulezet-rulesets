rule TTP_XOR_WriteProcessMemory_3af9 {
  strings:
    $key_3af9 = { 6d 8b [2] 5f a9 [2] 59 9c [2] 77 9c [2] 48 80 }

  condition:
    any of them
}