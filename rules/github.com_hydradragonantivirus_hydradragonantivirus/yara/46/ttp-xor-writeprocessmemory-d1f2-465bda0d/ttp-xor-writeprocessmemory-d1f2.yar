rule TTP_XOR_WriteProcessMemory_d1f2 {
  strings:
    $key_d1f2 = { 86 80 [2] b4 a2 [2] b2 97 [2] 9c 97 [2] a3 8b }

  condition:
    any of them
}