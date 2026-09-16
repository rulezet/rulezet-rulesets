rule TTP_XOR_WriteProcessMemory_e2a9 {
  strings:
    $key_e2a9 = { b5 db [2] 87 f9 [2] 81 cc [2] af cc [2] 90 d0 }

  condition:
    any of them
}