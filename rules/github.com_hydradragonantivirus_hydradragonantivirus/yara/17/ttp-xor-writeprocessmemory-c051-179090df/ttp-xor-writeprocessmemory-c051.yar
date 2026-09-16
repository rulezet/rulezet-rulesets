rule TTP_XOR_WriteProcessMemory_c051 {
  strings:
    $key_c051 = { 97 23 [2] a5 01 [2] a3 34 [2] 8d 34 [2] b2 28 }

  condition:
    any of them
}