rule TTP_XOR_WriteProcessMemory_52e2 {
  strings:
    $key_52e2 = { 05 90 [2] 37 b2 [2] 31 87 [2] 1f 87 [2] 20 9b }

  condition:
    any of them
}