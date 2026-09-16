rule TTP_XOR_WriteProcessMemory_e632 {
  strings:
    $key_e632 = { b1 40 [2] 83 62 [2] 85 57 [2] ab 57 [2] 94 4b }

  condition:
    any of them
}