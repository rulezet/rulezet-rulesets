rule TTP_XOR_WriteProcessMemory_5e05 {
  strings:
    $key_5e05 = { 09 77 [2] 3b 55 [2] 3d 60 [2] 13 60 [2] 2c 7c }

  condition:
    any of them
}