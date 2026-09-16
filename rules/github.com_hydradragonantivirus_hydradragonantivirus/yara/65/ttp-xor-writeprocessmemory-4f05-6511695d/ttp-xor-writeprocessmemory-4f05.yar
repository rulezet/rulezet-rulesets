rule TTP_XOR_WriteProcessMemory_4f05 {
  strings:
    $key_4f05 = { 18 77 [2] 2a 55 [2] 2c 60 [2] 02 60 [2] 3d 7c }

  condition:
    any of them
}