rule TTP_XOR_WriteProcessMemory_c131 {
  strings:
    $key_c131 = { 96 43 [2] a4 61 [2] a2 54 [2] 8c 54 [2] b3 48 }

  condition:
    any of them
}