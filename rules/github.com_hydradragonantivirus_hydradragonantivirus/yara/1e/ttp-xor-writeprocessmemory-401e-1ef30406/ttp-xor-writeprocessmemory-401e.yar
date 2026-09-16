rule TTP_XOR_WriteProcessMemory_401e {
  strings:
    $key_401e = { 17 6c [2] 25 4e [2] 23 7b [2] 0d 7b [2] 32 67 }

  condition:
    any of them
}