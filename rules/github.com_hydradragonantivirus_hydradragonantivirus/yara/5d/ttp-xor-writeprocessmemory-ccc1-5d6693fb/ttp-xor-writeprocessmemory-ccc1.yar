rule TTP_XOR_WriteProcessMemory_ccc1 {
  strings:
    $key_ccc1 = { 9b b3 [2] a9 91 [2] af a4 [2] 81 a4 [2] be b8 }

  condition:
    any of them
}