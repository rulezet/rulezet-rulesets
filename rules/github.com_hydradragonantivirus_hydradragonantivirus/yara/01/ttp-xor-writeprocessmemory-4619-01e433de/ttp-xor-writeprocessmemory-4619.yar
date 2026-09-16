rule TTP_XOR_WriteProcessMemory_4619 {
  strings:
    $key_4619 = { 11 6b [2] 23 49 [2] 25 7c [2] 0b 7c [2] 34 60 }

  condition:
    any of them
}