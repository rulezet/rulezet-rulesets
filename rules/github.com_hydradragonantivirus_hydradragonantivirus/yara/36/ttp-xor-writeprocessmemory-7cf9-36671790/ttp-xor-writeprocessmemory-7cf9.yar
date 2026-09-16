rule TTP_XOR_WriteProcessMemory_7cf9 {
  strings:
    $key_7cf9 = { 2b 8b [2] 19 a9 [2] 1f 9c [2] 31 9c [2] 0e 80 }

  condition:
    any of them
}