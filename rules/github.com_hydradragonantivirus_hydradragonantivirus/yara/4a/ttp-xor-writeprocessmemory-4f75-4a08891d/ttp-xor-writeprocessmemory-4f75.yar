rule TTP_XOR_WriteProcessMemory_4f75 {
  strings:
    $key_4f75 = { 18 07 [2] 2a 25 [2] 2c 10 [2] 02 10 [2] 3d 0c }

  condition:
    any of them
}