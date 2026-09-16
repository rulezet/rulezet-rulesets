rule TTP_XOR_WriteProcessMemory_732e {
  strings:
    $key_732e = { 24 5c [2] 16 7e [2] 10 4b [2] 3e 4b [2] 01 57 }

  condition:
    any of them
}