rule TTP_XOR_WriteProcessMemory_eea9 {
  strings:
    $key_eea9 = { b9 db [2] 8b f9 [2] 8d cc [2] a3 cc [2] 9c d0 }

  condition:
    any of them
}