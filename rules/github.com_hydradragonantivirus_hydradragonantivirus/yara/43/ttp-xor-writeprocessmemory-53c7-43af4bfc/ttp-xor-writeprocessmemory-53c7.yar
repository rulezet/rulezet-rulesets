rule TTP_XOR_WriteProcessMemory_53c7 {
  strings:
    $key_53c7 = { 04 b5 [2] 36 97 [2] 30 a2 [2] 1e a2 [2] 21 be }

  condition:
    any of them
}