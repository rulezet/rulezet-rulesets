rule TTP_XOR_WriteProcessMemory_2fe5 {
  strings:
    $key_2fe5 = { 78 97 [2] 4a b5 [2] 4c 80 [2] 62 80 [2] 5d 9c }

  condition:
    any of them
}