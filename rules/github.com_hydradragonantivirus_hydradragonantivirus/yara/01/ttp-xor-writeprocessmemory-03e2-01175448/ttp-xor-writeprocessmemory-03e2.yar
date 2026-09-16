rule TTP_XOR_WriteProcessMemory_03e2 {
  strings:
    $key_03e2 = { 54 90 [2] 66 b2 [2] 60 87 [2] 4e 87 [2] 71 9b }

  condition:
    any of them
}