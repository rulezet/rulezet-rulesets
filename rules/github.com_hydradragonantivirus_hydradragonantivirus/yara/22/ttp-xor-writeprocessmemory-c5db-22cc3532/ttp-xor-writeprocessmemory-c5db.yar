rule TTP_XOR_WriteProcessMemory_c5db {
  strings:
    $key_c5db = { 92 a9 [2] a0 8b [2] a6 be [2] 88 be [2] b7 a2 }

  condition:
    any of them
}