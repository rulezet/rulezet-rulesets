rule TTP_XOR_WriteProcessMemory_e4a9 {
  strings:
    $key_e4a9 = { b3 db [2] 81 f9 [2] 87 cc [2] a9 cc [2] 96 d0 }

  condition:
    any of them
}