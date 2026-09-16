rule TTP_XOR_WriteProcessMemory_0fc7 {
  strings:
    $key_0fc7 = { 58 b5 [2] 6a 97 [2] 6c a2 [2] 42 a2 [2] 7d be }

  condition:
    any of them
}