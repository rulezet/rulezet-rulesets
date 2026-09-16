rule TTP_XOR_WriteProcessMemory_ece5 {
  strings:
    $key_ece5 = { bb 97 [2] 89 b5 [2] 8f 80 [2] a1 80 [2] 9e 9c }

  condition:
    any of them
}