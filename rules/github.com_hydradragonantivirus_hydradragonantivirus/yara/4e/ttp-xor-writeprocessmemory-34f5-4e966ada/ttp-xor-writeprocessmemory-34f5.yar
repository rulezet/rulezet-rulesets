rule TTP_XOR_WriteProcessMemory_34f5 {
  strings:
    $key_34f5 = { 63 87 [2] 51 a5 [2] 57 90 [2] 79 90 [2] 46 8c }

  condition:
    any of them
}