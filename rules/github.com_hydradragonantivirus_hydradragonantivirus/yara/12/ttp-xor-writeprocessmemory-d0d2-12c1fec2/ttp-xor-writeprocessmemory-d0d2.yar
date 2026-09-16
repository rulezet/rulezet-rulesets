rule TTP_XOR_WriteProcessMemory_d0d2 {
  strings:
    $key_d0d2 = { 87 a0 [2] b5 82 [2] b3 b7 [2] 9d b7 [2] a2 ab }

  condition:
    any of them
}