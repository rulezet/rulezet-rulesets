rule TTP_XOR_WriteProcessMemory_7fc7 {
  strings:
    $key_7fc7 = { 28 b5 [2] 1a 97 [2] 1c a2 [2] 32 a2 [2] 0d be }

  condition:
    any of them
}