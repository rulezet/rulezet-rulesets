rule TTP_XOR_WriteProcessMemory_3a19 {
  strings:
    $key_3a19 = { 6d 6b [2] 5f 49 [2] 59 7c [2] 77 7c [2] 48 60 }

  condition:
    any of them
}