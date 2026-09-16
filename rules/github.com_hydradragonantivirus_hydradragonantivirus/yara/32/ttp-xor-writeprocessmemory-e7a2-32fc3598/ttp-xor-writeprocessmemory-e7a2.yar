rule TTP_XOR_WriteProcessMemory_e7a2 {
  strings:
    $key_e7a2 = { b0 d0 [2] 82 f2 [2] 84 c7 [2] aa c7 [2] 95 db }

  condition:
    any of them
}