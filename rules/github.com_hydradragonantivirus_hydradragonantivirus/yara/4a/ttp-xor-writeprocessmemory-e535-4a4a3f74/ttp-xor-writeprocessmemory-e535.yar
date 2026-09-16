rule TTP_XOR_WriteProcessMemory_e535 {
  strings:
    $key_e535 = { b2 47 [2] 80 65 [2] 86 50 [2] a8 50 [2] 97 4c }

  condition:
    any of them
}