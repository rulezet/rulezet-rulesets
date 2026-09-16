rule TTP_XOR_WriteProcessMemory_5e0c {
  strings:
    $key_5e0c = { 09 7e [2] 3b 5c [2] 3d 69 [2] 13 69 [2] 2c 75 }

  condition:
    any of them
}