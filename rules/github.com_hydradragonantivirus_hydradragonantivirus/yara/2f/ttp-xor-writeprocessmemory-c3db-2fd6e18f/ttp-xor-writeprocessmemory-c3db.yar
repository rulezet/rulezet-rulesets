rule TTP_XOR_WriteProcessMemory_c3db {
  strings:
    $key_c3db = { 94 a9 [2] a6 8b [2] a0 be [2] 8e be [2] b1 a2 }

  condition:
    any of them
}