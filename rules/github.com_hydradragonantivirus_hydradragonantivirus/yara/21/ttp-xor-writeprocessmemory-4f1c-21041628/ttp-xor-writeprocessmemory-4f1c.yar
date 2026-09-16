rule TTP_XOR_WriteProcessMemory_4f1c {
  strings:
    $key_4f1c = { 18 6e [2] 2a 4c [2] 2c 79 [2] 02 79 [2] 3d 65 }

  condition:
    any of them
}