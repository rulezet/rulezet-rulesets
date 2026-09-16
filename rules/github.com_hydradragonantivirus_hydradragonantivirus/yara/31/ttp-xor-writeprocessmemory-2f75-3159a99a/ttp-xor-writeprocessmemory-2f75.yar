rule TTP_XOR_WriteProcessMemory_2f75 {
  strings:
    $key_2f75 = { 78 07 [2] 4a 25 [2] 4c 10 [2] 62 10 [2] 5d 0c }

  condition:
    any of them
}