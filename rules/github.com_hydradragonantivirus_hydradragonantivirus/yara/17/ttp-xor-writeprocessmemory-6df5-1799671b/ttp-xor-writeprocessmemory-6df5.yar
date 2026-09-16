rule TTP_XOR_WriteProcessMemory_6df5 {
  strings:
    $key_6df5 = { 3a 87 [2] 08 a5 [2] 0e 90 [2] 20 90 [2] 1f 8c }

  condition:
    any of them
}