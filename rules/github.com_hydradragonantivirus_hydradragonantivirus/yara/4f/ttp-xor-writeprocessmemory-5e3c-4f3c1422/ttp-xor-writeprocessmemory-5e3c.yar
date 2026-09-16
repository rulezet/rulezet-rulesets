rule TTP_XOR_WriteProcessMemory_5e3c {
  strings:
    $key_5e3c = { 09 4e [2] 3b 6c [2] 3d 59 [2] 13 59 [2] 2c 45 }

  condition:
    any of them
}