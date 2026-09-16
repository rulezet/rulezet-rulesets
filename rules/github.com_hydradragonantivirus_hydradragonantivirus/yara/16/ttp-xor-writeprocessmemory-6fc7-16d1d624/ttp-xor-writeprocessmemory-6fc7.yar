rule TTP_XOR_WriteProcessMemory_6fc7 {
  strings:
    $key_6fc7 = { 38 b5 [2] 0a 97 [2] 0c a2 [2] 22 a2 [2] 1d be }

  condition:
    any of them
}