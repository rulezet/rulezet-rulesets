rule TTP_XOR_WriteProcessMemory_11e2 {
  strings:
    $key_11e2 = { 46 90 [2] 74 b2 [2] 72 87 [2] 5c 87 [2] 63 9b }

  condition:
    any of them
}