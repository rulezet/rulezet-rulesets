rule TTP_XOR_WriteProcessMemory_e509 {
  strings:
    $key_e509 = { b2 7b [2] 80 59 [2] 86 6c [2] a8 6c [2] 97 70 }

  condition:
    any of them
}