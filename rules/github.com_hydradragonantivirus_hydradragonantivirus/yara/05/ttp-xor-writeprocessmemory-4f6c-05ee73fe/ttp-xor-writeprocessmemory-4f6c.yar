rule TTP_XOR_WriteProcessMemory_4f6c {
  strings:
    $key_4f6c = { 18 1e [2] 2a 3c [2] 2c 09 [2] 02 09 [2] 3d 15 }

  condition:
    any of them
}