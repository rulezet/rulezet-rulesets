rule TTP_XOR_WriteProcessMemory_4f5e {
  strings:
    $key_4f5e = { 18 2c [2] 2a 0e [2] 2c 3b [2] 02 3b [2] 3d 27 }

  condition:
    any of them
}