rule TTP_XOR_WriteProcessMemory_5e5e {
  strings:
    $key_5e5e = { 09 2c [2] 3b 0e [2] 3d 3b [2] 13 3b [2] 2c 27 }

  condition:
    any of them
}