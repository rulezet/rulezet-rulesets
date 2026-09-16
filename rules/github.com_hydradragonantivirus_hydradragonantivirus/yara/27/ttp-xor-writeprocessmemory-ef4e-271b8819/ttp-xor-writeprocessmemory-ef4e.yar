rule TTP_XOR_WriteProcessMemory_ef4e {
  strings:
    $key_ef4e = { b8 3c [2] 8a 1e [2] 8c 2b [2] a2 2b [2] 9d 37 }

  condition:
    any of them
}