rule TTP_XOR_WriteProcessMemory_734e {
  strings:
    $key_734e = { 24 3c [2] 16 1e [2] 10 2b [2] 3e 2b [2] 01 37 }

  condition:
    any of them
}