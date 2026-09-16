rule TTP_XOR_WriteProcessMemory_5e2c {
  strings:
    $key_5e2c = { 09 5e [2] 3b 7c [2] 3d 49 [2] 13 49 [2] 2c 55 }

  condition:
    any of them
}