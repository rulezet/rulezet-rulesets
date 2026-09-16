rule TTP_XOR_WriteProcessMemory_7df5 {
  strings:
    $key_7df5 = { 2a 87 [2] 18 a5 [2] 1e 90 [2] 30 90 [2] 0f 8c }

  condition:
    any of them
}