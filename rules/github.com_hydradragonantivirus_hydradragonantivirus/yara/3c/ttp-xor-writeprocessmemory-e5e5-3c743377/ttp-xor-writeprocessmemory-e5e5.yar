rule TTP_XOR_WriteProcessMemory_e5e5 {
  strings:
    $key_e5e5 = { b2 97 [2] 80 b5 [2] 86 80 [2] a8 80 [2] 97 9c }

  condition:
    any of them
}