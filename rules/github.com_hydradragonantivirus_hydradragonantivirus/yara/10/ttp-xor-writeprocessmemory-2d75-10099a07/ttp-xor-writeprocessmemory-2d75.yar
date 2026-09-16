rule TTP_XOR_WriteProcessMemory_2d75 {
  strings:
    $key_2d75 = { 7a 07 [2] 48 25 [2] 4e 10 [2] 60 10 [2] 5f 0c }

  condition:
    any of them
}