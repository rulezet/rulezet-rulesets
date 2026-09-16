rule TTP_XOR_WriteProcessMemory_5e6e {
  strings:
    $key_5e6e = { 09 1c [2] 3b 3e [2] 3d 0b [2] 13 0b [2] 2c 17 }

  condition:
    any of them
}