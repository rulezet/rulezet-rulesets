rule TTP_XOR_WriteProcessMemory_c6a9 {
  strings:
    $key_c6a9 = { 91 db [2] a3 f9 [2] a5 cc [2] 8b cc [2] b4 d0 }

  condition:
    any of them
}