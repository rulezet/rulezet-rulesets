rule TTP_XOR_WriteProcessMemory_c170 {
  strings:
    $key_c170 = { 96 02 [2] a4 20 [2] a2 15 [2] 8c 15 [2] b3 09 }

  condition:
    any of them
}