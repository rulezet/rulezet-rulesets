rule TTP_XOR_WriteProcessMemory_e6f2 {
  strings:
    $key_e6f2 = { b1 80 [2] 83 a2 [2] 85 97 [2] ab 97 [2] 94 8b }

  condition:
    any of them
}