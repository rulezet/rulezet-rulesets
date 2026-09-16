rule TTP_XOR_WriteProcessMemory_504e {
  strings:
    $key_504e = { 07 3c [2] 35 1e [2] 33 2b [2] 1d 2b [2] 22 37 }

  condition:
    any of them
}