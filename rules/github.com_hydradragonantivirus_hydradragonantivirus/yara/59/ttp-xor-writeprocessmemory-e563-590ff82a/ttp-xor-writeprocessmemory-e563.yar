rule TTP_XOR_WriteProcessMemory_e563 {
  strings:
    $key_e563 = { b2 11 [2] 80 33 [2] 86 06 [2] a8 06 [2] 97 1a }

  condition:
    any of them
}