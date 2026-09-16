rule TTP_XOR_WriteProcessMemory_76c7 {
  strings:
    $key_76c7 = { 21 b5 [2] 13 97 [2] 15 a2 [2] 3b a2 [2] 04 be }

  condition:
    any of them
}