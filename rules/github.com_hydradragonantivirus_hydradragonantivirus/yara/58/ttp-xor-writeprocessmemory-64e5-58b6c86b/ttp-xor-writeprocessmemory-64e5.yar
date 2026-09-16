rule TTP_XOR_WriteProcessMemory_64e5 {
  strings:
    $key_64e5 = { 33 97 [2] 01 b5 [2] 07 80 [2] 29 80 [2] 16 9c }

  condition:
    any of them
}