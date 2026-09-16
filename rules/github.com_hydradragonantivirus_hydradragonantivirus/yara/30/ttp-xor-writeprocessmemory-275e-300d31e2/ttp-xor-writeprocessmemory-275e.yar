rule TTP_XOR_WriteProcessMemory_275e {
  strings:
    $key_275e = { 70 2c [2] 42 0e [2] 44 3b [2] 6a 3b [2] 55 27 }

  condition:
    any of them
}