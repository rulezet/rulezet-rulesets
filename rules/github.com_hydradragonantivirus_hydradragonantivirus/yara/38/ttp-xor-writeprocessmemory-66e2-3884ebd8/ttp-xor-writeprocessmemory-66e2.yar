rule TTP_XOR_WriteProcessMemory_66e2 {
  strings:
    $key_66e2 = { 31 90 [2] 03 b2 [2] 05 87 [2] 2b 87 [2] 14 9b }

  condition:
    any of them
}