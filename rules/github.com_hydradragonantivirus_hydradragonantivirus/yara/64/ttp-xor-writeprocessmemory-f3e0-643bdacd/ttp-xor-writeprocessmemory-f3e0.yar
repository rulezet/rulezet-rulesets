rule TTP_XOR_WriteProcessMemory_f3e0 {
  strings:
    $key_f3e0 = { a4 92 [2] 96 b0 [2] 90 85 [2] be 85 [2] 81 99 }

  condition:
    any of them
}