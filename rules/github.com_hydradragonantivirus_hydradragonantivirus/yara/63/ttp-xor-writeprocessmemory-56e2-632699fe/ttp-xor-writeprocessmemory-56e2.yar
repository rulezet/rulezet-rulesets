rule TTP_XOR_WriteProcessMemory_56e2 {
  strings:
    $key_56e2 = { 01 90 [2] 33 b2 [2] 35 87 [2] 1b 87 [2] 24 9b }

  condition:
    any of them
}