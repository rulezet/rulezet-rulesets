rule TTP_XOR_WriteProcessMemory_78e2 {
  strings:
    $key_78e2 = { 2f 90 [2] 1d b2 [2] 1b 87 [2] 35 87 [2] 0a 9b }

  condition:
    any of them
}