rule TTP_XOR_WriteProcessMemory_e5ce {
  strings:
    $key_e5ce = { b2 bc [2] 80 9e [2] 86 ab [2] a8 ab [2] 97 b7 }

  condition:
    any of them
}