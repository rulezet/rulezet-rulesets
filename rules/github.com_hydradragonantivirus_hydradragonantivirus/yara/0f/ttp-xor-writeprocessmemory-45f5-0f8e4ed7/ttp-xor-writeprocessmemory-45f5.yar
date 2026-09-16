rule TTP_XOR_WriteProcessMemory_45f5 {
  strings:
    $key_45f5 = { 12 87 [2] 20 a5 [2] 26 90 [2] 08 90 [2] 37 8c }

  condition:
    any of them
}