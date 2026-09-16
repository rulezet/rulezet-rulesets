rule TTP_XOR_WriteProcessMemory_0ef9 {
  strings:
    $key_0ef9 = { 59 8b [2] 6b a9 [2] 6d 9c [2] 43 9c [2] 7c 80 }

  condition:
    any of them
}