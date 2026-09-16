rule TTP_XOR_WriteProcessMemory_e560 {
  strings:
    $key_e560 = { b2 12 [2] 80 30 [2] 86 05 [2] a8 05 [2] 97 19 }

  condition:
    any of them
}