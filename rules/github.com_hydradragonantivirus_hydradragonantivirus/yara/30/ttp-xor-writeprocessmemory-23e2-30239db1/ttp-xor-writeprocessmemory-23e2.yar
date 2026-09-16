rule TTP_XOR_WriteProcessMemory_23e2 {
  strings:
    $key_23e2 = { 74 90 [2] 46 b2 [2] 40 87 [2] 6e 87 [2] 51 9b }

  condition:
    any of them
}