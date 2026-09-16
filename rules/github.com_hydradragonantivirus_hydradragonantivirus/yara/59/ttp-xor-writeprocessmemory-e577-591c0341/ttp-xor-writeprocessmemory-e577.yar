rule TTP_XOR_WriteProcessMemory_e577 {
  strings:
    $key_e577 = { b2 05 [2] 80 27 [2] 86 12 [2] a8 12 [2] 97 0e }

  condition:
    any of them
}