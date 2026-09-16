rule TTP_XOR_WriteProcessMemory_e525 {
  strings:
    $key_e525 = { b2 57 [2] 80 75 [2] 86 40 [2] a8 40 [2] 97 5c }

  condition:
    any of them
}