rule TTP_XOR_WriteProcessMemory_01e2 {
  strings:
    $key_01e2 = { 56 90 [2] 64 b2 [2] 62 87 [2] 4c 87 [2] 73 9b }

  condition:
    any of them
}