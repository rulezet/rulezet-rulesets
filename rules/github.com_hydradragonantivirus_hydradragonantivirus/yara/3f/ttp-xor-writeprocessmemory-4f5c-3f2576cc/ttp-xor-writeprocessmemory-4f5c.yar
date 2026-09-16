rule TTP_XOR_WriteProcessMemory_4f5c {
  strings:
    $key_4f5c = { 18 2e [2] 2a 0c [2] 2c 39 [2] 02 39 [2] 3d 25 }

  condition:
    any of them
}