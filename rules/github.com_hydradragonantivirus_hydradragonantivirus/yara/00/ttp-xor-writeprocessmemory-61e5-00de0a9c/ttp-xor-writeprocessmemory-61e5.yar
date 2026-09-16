rule TTP_XOR_WriteProcessMemory_61e5 {
  strings:
    $key_61e5 = { 36 97 [2] 04 b5 [2] 02 80 [2] 2c 80 [2] 13 9c }

  condition:
    any of them
}