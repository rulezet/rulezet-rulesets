rule TTP_XOR_WriteProcessMemory_1fc7 {
  strings:
    $key_1fc7 = { 48 b5 [2] 7a 97 [2] 7c a2 [2] 52 a2 [2] 6d be }

  condition:
    any of them
}