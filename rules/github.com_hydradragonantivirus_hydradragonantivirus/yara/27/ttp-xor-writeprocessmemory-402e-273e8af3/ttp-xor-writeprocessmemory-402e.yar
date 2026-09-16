rule TTP_XOR_WriteProcessMemory_402e {
  strings:
    $key_402e = { 17 5c [2] 25 7e [2] 23 4b [2] 0d 4b [2] 32 57 }

  condition:
    any of them
}