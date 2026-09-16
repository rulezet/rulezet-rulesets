rule TTP_XOR_WriteProcessMemory_31c7 {
  strings:
    $key_31c7 = { 66 b5 [2] 54 97 [2] 52 a2 [2] 7c a2 [2] 43 be }

  condition:
    any of them
}