rule TTP_XOR_WriteProcessMemory_4f7c {
  strings:
    $key_4f7c = { 18 0e [2] 2a 2c [2] 2c 19 [2] 02 19 [2] 3d 05 }

  condition:
    any of them
}