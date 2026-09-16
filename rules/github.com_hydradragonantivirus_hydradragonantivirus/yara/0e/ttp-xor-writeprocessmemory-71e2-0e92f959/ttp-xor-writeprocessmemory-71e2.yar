rule TTP_XOR_WriteProcessMemory_71e2 {
  strings:
    $key_71e2 = { 26 90 [2] 14 b2 [2] 12 87 [2] 3c 87 [2] 03 9b }

  condition:
    any of them
}