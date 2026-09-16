rule TTP_XOR_WriteProcessMemory_3ae9 {
  strings:
    $key_3ae9 = { 6d 9b [2] 5f b9 [2] 59 8c [2] 77 8c [2] 48 90 }

  condition:
    any of them
}