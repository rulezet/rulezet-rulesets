rule TTP_XOR_WriteProcessMemory_534e {
  strings:
    $key_534e = { 04 3c [2] 36 1e [2] 30 2b [2] 1e 2b [2] 21 37 }

  condition:
    any of them
}