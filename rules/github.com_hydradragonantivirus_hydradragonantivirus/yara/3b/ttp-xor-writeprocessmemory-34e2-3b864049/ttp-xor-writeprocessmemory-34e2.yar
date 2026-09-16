rule TTP_XOR_WriteProcessMemory_34e2 {
  strings:
    $key_34e2 = { 63 90 [2] 51 b2 [2] 57 87 [2] 79 87 [2] 46 9b }

  condition:
    any of them
}