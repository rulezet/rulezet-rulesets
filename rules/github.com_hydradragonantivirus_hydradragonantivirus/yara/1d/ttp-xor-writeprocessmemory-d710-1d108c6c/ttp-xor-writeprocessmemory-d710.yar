rule TTP_XOR_WriteProcessMemory_d710 {
  strings:
    $key_d710 = { 80 62 [2] b2 40 [2] b4 75 [2] 9a 75 [2] a5 69 }

  condition:
    any of them
}