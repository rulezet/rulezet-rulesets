rule TTP_XOR_WriteProcessMemory_44f5 {
  strings:
    $key_44f5 = { 13 87 [2] 21 a5 [2] 27 90 [2] 09 90 [2] 36 8c }

  condition:
    any of them
}