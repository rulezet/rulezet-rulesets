rule TTP_XOR_WriteProcessMemory_e547 {
  strings:
    $key_e547 = { b2 35 [2] 80 17 [2] 86 22 [2] a8 22 [2] 97 3e }

  condition:
    any of them
}