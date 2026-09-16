rule TTP_XOR_WriteProcessMemory_f3e2 {
  strings:
    $key_f3e2 = { a4 90 [2] 96 b2 [2] 90 87 [2] be 87 [2] 81 9b }

  condition:
    any of them
}