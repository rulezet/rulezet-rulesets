rule TTP_XOR_WriteProcessMemory_6de2 {
  strings:
    $key_6de2 = { 3a 90 [2] 08 b2 [2] 0e 87 [2] 20 87 [2] 1f 9b }

  condition:
    any of them
}