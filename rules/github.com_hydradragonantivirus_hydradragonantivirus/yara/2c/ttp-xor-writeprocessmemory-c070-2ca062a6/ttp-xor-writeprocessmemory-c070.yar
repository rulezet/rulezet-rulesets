rule TTP_XOR_WriteProcessMemory_c070 {
  strings:
    $key_c070 = { 97 02 [2] a5 20 [2] a3 15 [2] 8d 15 [2] b2 09 }

  condition:
    any of them
}