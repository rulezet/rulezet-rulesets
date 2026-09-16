rule TTP_XOR_WriteProcessMemory_6d4e {
  strings:
    $key_6d4e = { 3a 3c [2] 08 1e [2] 0e 2b [2] 20 2b [2] 1f 37 }

  condition:
    any of them
}