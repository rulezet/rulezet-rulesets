rule TTP_XOR_WriteProcessMemory_1f75 {
  strings:
    $key_1f75 = { 48 07 [2] 7a 25 [2] 7c 10 [2] 52 10 [2] 6d 0c }

  condition:
    any of them
}