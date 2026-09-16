rule TTP_XOR_WriteProcessMemory_e643 {
  strings:
    $key_e643 = { b1 31 [2] 83 13 [2] 85 26 [2] ab 26 [2] 94 3a }

  condition:
    any of them
}