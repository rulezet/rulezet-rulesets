rule TTP_XOR_WriteProcessMemory_4f45 {
  strings:
    $key_4f45 = { 18 37 [2] 2a 15 [2] 2c 20 [2] 02 20 [2] 3d 3c }

  condition:
    any of them
}