rule TTP_XOR_WriteProcessMemory_e2a2 {
  strings:
    $key_e2a2 = { b5 d0 [2] 87 f2 [2] 81 c7 [2] af c7 [2] 90 db }

  condition:
    any of them
}