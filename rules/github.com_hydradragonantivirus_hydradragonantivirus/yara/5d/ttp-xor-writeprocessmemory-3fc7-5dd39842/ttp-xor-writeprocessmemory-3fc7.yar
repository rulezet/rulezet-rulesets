rule TTP_XOR_WriteProcessMemory_3fc7 {
  strings:
    $key_3fc7 = { 68 b5 [2] 5a 97 [2] 5c a2 [2] 72 a2 [2] 4d be }

  condition:
    any of them
}