rule TTP_XOR_WriteProcessMemory_4f0c {
  strings:
    $key_4f0c = { 18 7e [2] 2a 5c [2] 2c 69 [2] 02 69 [2] 3d 75 }

  condition:
    any of them
}