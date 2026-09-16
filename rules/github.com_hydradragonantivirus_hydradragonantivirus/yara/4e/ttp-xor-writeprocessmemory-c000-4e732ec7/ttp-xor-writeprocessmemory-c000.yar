rule TTP_XOR_WriteProcessMemory_c000 {
  strings:
    $key_c000 = { 97 72 [2] a5 50 [2] a3 65 [2] 8d 65 [2] b2 79 }

  condition:
    any of them
}