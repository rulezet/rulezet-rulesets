rule TTP_XOR_WriteProcessMemory_26c7 {
  strings:
    $key_26c7 = { 71 b5 [2] 43 97 [2] 45 a2 [2] 6b a2 [2] 54 be }

  condition:
    any of them
}