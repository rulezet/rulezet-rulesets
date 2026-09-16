rule TTP_XOR_WriteProcessMemory_e4e5 {
  strings:
    $key_e4e5 = { b3 97 [2] 81 b5 [2] 87 80 [2] a9 80 [2] 96 9c }

  condition:
    any of them
}