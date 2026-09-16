rule TTP_XOR_WriteProcessMemory_45e2 {
  strings:
    $key_45e2 = { 12 90 [2] 20 b2 [2] 26 87 [2] 08 87 [2] 37 9b }

  condition:
    any of them
}