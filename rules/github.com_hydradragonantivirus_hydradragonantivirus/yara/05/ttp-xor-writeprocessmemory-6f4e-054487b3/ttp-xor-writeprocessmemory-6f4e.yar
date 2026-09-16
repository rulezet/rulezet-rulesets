rule TTP_XOR_WriteProcessMemory_6f4e {
  strings:
    $key_6f4e = { 38 3c [2] 0a 1e [2] 0c 2b [2] 22 2b [2] 1d 37 }

  condition:
    any of them
}