rule TTP_XOR_WriteProcessMemory_3509 {
  strings:
    $key_3509 = { 62 7b [2] 50 59 [2] 56 6c [2] 78 6c [2] 47 70 }

  condition:
    any of them
}