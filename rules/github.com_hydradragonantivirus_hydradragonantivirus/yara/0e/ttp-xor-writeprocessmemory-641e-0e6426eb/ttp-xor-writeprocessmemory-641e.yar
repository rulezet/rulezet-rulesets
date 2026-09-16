rule TTP_XOR_WriteProcessMemory_641e {
  strings:
    $key_641e = { 33 6c [2] 01 4e [2] 07 7b [2] 29 7b [2] 16 67 }

  condition:
    any of them
}