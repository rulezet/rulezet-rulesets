rule TTP_XOR_WriteProcessMemory_28e2 {
  strings:
    $key_28e2 = { 7f 90 [2] 4d b2 [2] 4b 87 [2] 65 87 [2] 5a 9b }

  condition:
    any of them
}