rule TTP_XOR_WriteProcessMemory_7b0e {
  strings:
    $key_7b0e = { 2c 7c [2] 1e 5e [2] 18 6b [2] 36 6b [2] 09 77 }

  condition:
    any of them
}