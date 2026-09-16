rule TTP_XOR_WriteProcessMemory_d6db {
  strings:
    $key_d6db = { 81 a9 [2] b3 8b [2] b5 be [2] 9b be [2] a4 a2 }

  condition:
    any of them
}