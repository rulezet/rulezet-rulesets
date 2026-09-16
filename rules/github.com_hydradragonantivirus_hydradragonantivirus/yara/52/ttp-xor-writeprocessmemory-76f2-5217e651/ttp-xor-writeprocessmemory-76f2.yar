rule TTP_XOR_WriteProcessMemory_76f2 {
  strings:
    $key_76f2 = { 21 80 [2] 13 a2 [2] 15 97 [2] 3b 97 [2] 04 8b }

  condition:
    any of them
}