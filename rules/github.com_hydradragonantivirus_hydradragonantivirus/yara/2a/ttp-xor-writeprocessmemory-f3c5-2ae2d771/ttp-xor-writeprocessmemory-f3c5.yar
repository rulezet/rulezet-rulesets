rule TTP_XOR_WriteProcessMemory_f3c5 {
  strings:
    $key_f3c5 = { a4 b7 [2] 96 95 [2] 90 a0 [2] be a0 [2] 81 bc }

  condition:
    any of them
}