rule TTP_XOR_WriteProcessMemory_21c7 {
  strings:
    $key_21c7 = { 76 b5 [2] 44 97 [2] 42 a2 [2] 6c a2 [2] 53 be }

  condition:
    any of them
}