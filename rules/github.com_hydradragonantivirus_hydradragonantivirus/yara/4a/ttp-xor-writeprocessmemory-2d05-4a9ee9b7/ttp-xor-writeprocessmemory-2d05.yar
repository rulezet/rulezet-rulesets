rule TTP_XOR_WriteProcessMemory_2d05 {
  strings:
    $key_2d05 = { 7a 77 [2] 48 55 [2] 4e 60 [2] 60 60 [2] 5f 7c }

  condition:
    any of them
}