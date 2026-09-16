rule TTP_XOR_WriteProcessMemory_c041 {
  strings:
    $key_c041 = { 97 33 [2] a5 11 [2] a3 24 [2] 8d 24 [2] b2 38 }

  condition:
    any of them
}