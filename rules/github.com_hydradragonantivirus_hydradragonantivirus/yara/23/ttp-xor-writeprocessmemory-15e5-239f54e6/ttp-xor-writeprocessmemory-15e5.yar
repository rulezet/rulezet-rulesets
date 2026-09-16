rule TTP_XOR_WriteProcessMemory_15e5 {
  strings:
    $key_15e5 = { 42 97 [2] 70 b5 [2] 76 80 [2] 58 80 [2] 67 9c }

  condition:
    any of them
}