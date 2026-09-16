rule TTP_XOR_WriteProcessMemory_2d45 {
  strings:
    $key_2d45 = { 7a 37 [2] 48 15 [2] 4e 20 [2] 60 20 [2] 5f 3c }

  condition:
    any of them
}