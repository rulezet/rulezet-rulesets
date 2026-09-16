rule TTP_XOR_WriteProcessMemory_6d5e {
  strings:
    $key_6d5e = { 3a 2c [2] 08 0e [2] 0e 3b [2] 20 3b [2] 1f 27 }

  condition:
    any of them
}