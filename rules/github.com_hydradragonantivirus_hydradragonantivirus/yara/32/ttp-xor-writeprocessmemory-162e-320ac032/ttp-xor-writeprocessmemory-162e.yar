rule TTP_XOR_WriteProcessMemory_162e {
  strings:
    $key_162e = { 41 5c [2] 73 7e [2] 75 4b [2] 5b 4b [2] 64 57 }

  condition:
    any of them
}