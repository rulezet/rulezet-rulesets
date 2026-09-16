rule TTP_XOR_WriteProcessMemory_34c7 {
  strings:
    $key_34c7 = { 63 b5 [2] 51 97 [2] 57 a2 [2] 79 a2 [2] 46 be }

  condition:
    any of them
}