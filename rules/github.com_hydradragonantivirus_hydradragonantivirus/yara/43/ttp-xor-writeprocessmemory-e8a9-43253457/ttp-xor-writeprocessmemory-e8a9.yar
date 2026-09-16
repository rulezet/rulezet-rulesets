rule TTP_XOR_WriteProcessMemory_e8a9 {
  strings:
    $key_e8a9 = { bf db [2] 8d f9 [2] 8b cc [2] a5 cc [2] 9a d0 }

  condition:
    any of them
}