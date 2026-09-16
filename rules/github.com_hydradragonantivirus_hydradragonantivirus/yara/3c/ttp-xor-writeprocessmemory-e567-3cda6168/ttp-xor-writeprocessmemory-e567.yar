rule TTP_XOR_WriteProcessMemory_e567 {
  strings:
    $key_e567 = { b2 15 [2] 80 37 [2] 86 02 [2] a8 02 [2] 97 1e }

  condition:
    any of them
}