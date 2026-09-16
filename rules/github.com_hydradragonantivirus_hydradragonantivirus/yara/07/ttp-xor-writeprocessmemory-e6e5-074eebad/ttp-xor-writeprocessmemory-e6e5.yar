rule TTP_XOR_WriteProcessMemory_e6e5 {
  strings:
    $key_e6e5 = { b1 97 [2] 83 b5 [2] 85 80 [2] ab 80 [2] 94 9c }

  condition:
    any of them
}