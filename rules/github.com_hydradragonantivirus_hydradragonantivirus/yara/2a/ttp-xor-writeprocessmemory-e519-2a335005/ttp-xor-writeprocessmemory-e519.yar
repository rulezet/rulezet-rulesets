rule TTP_XOR_WriteProcessMemory_e519 {
  strings:
    $key_e519 = { b2 6b [2] 80 49 [2] 86 7c [2] a8 7c [2] 97 60 }

  condition:
    any of them
}