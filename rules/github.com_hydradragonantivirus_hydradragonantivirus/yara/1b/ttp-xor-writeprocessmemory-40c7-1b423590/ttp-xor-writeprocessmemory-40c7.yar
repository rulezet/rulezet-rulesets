rule TTP_XOR_WriteProcessMemory_40c7 {
  strings:
    $key_40c7 = { 17 b5 [2] 25 97 [2] 23 a2 [2] 0d a2 [2] 32 be }

  condition:
    any of them
}