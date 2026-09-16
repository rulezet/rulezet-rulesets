rule TTP_XOR_WriteProcessMemory_7c5e {
  strings:
    $key_7c5e = { 2b 2c [2] 19 0e [2] 1f 3b [2] 31 3b [2] 0e 27 }

  condition:
    any of them
}