rule TTP_XOR_WriteProcessMemory_1f4e {
  strings:
    $key_1f4e = { 48 3c [2] 7a 1e [2] 7c 2b [2] 52 2b [2] 6d 37 }

  condition:
    any of them
}