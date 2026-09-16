rule TTP_XOR_WriteProcessMemory_c0db {
  strings:
    $key_c0db = { 97 a9 [2] a5 8b [2] a3 be [2] 8d be [2] b2 a2 }

  condition:
    any of them
}