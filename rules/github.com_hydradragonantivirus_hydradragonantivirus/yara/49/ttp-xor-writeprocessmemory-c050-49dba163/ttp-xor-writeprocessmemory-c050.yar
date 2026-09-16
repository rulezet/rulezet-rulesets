rule TTP_XOR_WriteProcessMemory_c050 {
  strings:
    $key_c050 = { 97 22 [2] a5 00 [2] a3 35 [2] 8d 35 [2] b2 29 }

  condition:
    any of them
}