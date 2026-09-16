rule TTP_XOR_WriteProcessMemory_5e4e {
  strings:
    $key_5e4e = { 09 3c [2] 3b 1e [2] 3d 2b [2] 13 2b [2] 2c 37 }

  condition:
    any of them
}