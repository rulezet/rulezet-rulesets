rule TTP_XOR_WriteProcessMemory_07c7 {
  strings:
    $key_07c7 = { 50 b5 [2] 62 97 [2] 64 a2 [2] 4a a2 [2] 75 be }

  condition:
    any of them
}