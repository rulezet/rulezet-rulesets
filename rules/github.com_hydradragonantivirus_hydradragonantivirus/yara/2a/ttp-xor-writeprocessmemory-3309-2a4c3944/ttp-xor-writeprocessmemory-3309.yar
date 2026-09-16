rule TTP_XOR_WriteProcessMemory_3309 {
  strings:
    $key_3309 = { 64 7b [2] 56 59 [2] 50 6c [2] 7e 6c [2] 41 70 }

  condition:
    any of them
}