rule TTP_XOR_WriteProcessMemory_412e {
  strings:
    $key_412e = { 16 5c [2] 24 7e [2] 22 4b [2] 0c 4b [2] 33 57 }

  condition:
    any of them
}