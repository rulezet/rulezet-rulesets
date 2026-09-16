rule TTP_XOR_WriteProcessMemory_d7f2 {
  strings:
    $key_d7f2 = { 80 80 [2] b2 a2 [2] b4 97 [2] 9a 97 [2] a5 8b }

  condition:
    any of them
}