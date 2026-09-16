rule TTP_XOR_WriteProcessMemory_645e {
  strings:
    $key_645e = { 33 2c [2] 01 0e [2] 07 3b [2] 29 3b [2] 16 27 }

  condition:
    any of them
}