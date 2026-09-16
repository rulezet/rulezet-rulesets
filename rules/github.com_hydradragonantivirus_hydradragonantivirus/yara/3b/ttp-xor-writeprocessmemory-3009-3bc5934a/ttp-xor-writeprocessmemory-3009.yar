rule TTP_XOR_WriteProcessMemory_3009 {
  strings:
    $key_3009 = { 67 7b [2] 55 59 [2] 53 6c [2] 7d 6c [2] 42 70 }

  condition:
    any of them
}