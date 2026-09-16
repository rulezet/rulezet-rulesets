rule TTP_XOR_WriteProcessMemory_4e05 {
  strings:
    $key_4e05 = { 19 77 [2] 2b 55 [2] 2d 60 [2] 03 60 [2] 3c 7c }

  condition:
    any of them
}