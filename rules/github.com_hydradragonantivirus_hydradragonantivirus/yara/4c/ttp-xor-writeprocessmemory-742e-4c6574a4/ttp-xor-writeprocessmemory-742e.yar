rule TTP_XOR_WriteProcessMemory_742e {
  strings:
    $key_742e = { 23 5c [2] 11 7e [2] 17 4b [2] 39 4b [2] 06 57 }

  condition:
    any of them
}