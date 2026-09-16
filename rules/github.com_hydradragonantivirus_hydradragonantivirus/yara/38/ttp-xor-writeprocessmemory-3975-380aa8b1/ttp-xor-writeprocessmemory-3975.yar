rule TTP_XOR_WriteProcessMemory_3975 {
  strings:
    $key_3975 = { 6e 07 [2] 5c 25 [2] 5a 10 [2] 74 10 [2] 4b 0c }

  condition:
    any of them
}