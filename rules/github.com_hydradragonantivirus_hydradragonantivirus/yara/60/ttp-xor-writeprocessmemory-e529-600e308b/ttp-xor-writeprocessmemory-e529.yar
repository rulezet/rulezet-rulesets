rule TTP_XOR_WriteProcessMemory_e529 {
  strings:
    $key_e529 = { b2 5b [2] 80 79 [2] 86 4c [2] a8 4c [2] 97 50 }

  condition:
    any of them
}