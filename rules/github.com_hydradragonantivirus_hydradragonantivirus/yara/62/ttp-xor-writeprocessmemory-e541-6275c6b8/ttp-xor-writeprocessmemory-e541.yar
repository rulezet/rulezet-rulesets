rule TTP_XOR_WriteProcessMemory_e541 {
  strings:
    $key_e541 = { b2 33 [2] 80 11 [2] 86 24 [2] a8 24 [2] 97 38 }

  condition:
    any of them
}