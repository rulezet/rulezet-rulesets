rule TTP_XOR_WriteProcessMemory_7409 {
  strings:
    $key_7409 = { 23 7b [2] 11 59 [2] 17 6c [2] 39 6c [2] 06 70 }

  condition:
    any of them
}