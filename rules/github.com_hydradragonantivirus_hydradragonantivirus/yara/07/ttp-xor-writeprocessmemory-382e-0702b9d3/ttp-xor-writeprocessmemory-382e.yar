rule TTP_XOR_WriteProcessMemory_382e {
  strings:
    $key_382e = { 6f 5c [2] 5d 7e [2] 5b 4b [2] 75 4b [2] 4a 57 }

  condition:
    any of them
}