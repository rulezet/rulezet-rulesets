rule TTP_XOR_WriteProcessMemory_e5f9 {
  strings:
    $key_e5f9 = { b2 8b [2] 80 a9 [2] 86 9c [2] a8 9c [2] 97 80 }

  condition:
    any of them
}