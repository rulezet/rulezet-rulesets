rule TTP_XOR_WriteProcessMemory_36e2 {
  strings:
    $key_36e2 = { 61 90 [2] 53 b2 [2] 55 87 [2] 7b 87 [2] 44 9b }

  condition:
    any of them
}