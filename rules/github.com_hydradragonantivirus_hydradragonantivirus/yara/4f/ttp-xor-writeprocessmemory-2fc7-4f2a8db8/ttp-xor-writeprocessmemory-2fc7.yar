rule TTP_XOR_WriteProcessMemory_2fc7 {
  strings:
    $key_2fc7 = { 78 b5 [2] 4a 97 [2] 4c a2 [2] 62 a2 [2] 5d be }

  condition:
    any of them
}