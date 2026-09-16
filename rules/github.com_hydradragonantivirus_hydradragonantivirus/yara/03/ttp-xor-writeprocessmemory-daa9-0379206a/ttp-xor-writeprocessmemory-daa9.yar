rule TTP_XOR_WriteProcessMemory_daa9 {
  strings:
    $key_daa9 = { 8d db [2] bf f9 [2] b9 cc [2] 97 cc [2] a8 d0 }

  condition:
    any of them
}