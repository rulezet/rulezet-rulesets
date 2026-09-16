rule TTP_XOR_WriteProcessMemory_ccc6 {
  strings:
    $key_ccc6 = { 9b b4 [2] a9 96 [2] af a3 [2] 81 a3 [2] be bf }

  condition:
    any of them
}