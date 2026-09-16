rule TTP_XOR_WriteProcessMemory_e510 {
  strings:
    $key_e510 = { b2 62 [2] 80 40 [2] 86 75 [2] a8 75 [2] 97 69 }

  condition:
    any of them
}