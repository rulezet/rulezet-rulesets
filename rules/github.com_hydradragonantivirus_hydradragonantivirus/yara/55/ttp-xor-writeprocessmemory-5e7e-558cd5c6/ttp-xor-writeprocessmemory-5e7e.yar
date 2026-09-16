rule TTP_XOR_WriteProcessMemory_5e7e {
  strings:
    $key_5e7e = { 09 0c [2] 3b 2e [2] 3d 1b [2] 13 1b [2] 2c 07 }

  condition:
    any of them
}