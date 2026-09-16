rule TTP_XOR_WriteProcessMemory_d170 {
  strings:
    $key_d170 = { 86 02 [2] b4 20 [2] b2 15 [2] 9c 15 [2] a3 09 }

  condition:
    any of them
}