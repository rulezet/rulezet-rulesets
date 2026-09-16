rule TTP_XOR_WriteProcessMemory_e5dd {
  strings:
    $key_e5dd = { b2 af [2] 80 8d [2] 86 b8 [2] a8 b8 [2] 97 a4 }

  condition:
    any of them
}