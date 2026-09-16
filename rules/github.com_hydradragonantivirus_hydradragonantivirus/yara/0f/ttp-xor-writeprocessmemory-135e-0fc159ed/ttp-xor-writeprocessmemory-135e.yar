rule TTP_XOR_WriteProcessMemory_135e {
  strings:
    $key_135e = { 44 2c [2] 76 0e [2] 70 3b [2] 5e 3b [2] 61 27 }

  condition:
    any of them
}