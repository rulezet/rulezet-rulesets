rule TTP_XOR_WriteProcessMemory_5e0e {
  strings:
    $key_5e0e = { 09 7c [2] 3b 5e [2] 3d 6b [2] 13 6b [2] 2c 77 }

  condition:
    any of them
}