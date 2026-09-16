rule TTP_XOR_WriteProcessMemory_25c7 {
  strings:
    $key_25c7 = { 72 b5 [2] 40 97 [2] 46 a2 [2] 68 a2 [2] 57 be }

  condition:
    any of them
}