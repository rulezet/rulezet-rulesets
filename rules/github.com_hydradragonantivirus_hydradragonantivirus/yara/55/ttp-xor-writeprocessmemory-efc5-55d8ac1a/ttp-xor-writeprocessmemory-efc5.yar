rule TTP_XOR_WriteProcessMemory_efc5 {
  strings:
    $key_efc5 = { b8 b7 [2] 8a 95 [2] 8c a0 [2] a2 a0 [2] 9d bc }

  condition:
    any of them
}