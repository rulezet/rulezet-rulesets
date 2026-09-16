rule TTP_XOR_WriteProcessMemory_4f29 {
  strings:
    $key_4f29 = { 18 5b [2] 2a 79 [2] 2c 4c [2] 02 4c [2] 3d 50 }

  condition:
    any of them
}