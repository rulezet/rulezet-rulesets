rule TTP_XOR_WriteProcessMemory_e5c7 {
  strings:
    $key_e5c7 = { b2 b5 [2] 80 97 [2] 86 a2 [2] a8 a2 [2] 97 be }

  condition:
    any of them
}