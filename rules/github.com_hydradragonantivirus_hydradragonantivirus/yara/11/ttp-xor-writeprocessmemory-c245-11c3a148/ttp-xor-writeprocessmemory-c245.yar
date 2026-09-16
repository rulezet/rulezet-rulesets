rule TTP_XOR_WriteProcessMemory_c245 {
  strings:
    $key_c245 = { 95 37 [2] a7 15 [2] a1 20 [2] 8f 20 [2] b0 3c }

  condition:
    any of them
}