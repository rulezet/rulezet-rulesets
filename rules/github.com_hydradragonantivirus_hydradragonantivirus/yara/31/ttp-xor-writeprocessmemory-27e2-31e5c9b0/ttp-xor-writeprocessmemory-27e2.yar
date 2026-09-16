rule TTP_XOR_WriteProcessMemory_27e2 {
  strings:
    $key_27e2 = { 70 90 [2] 42 b2 [2] 44 87 [2] 6a 87 [2] 55 9b }

  condition:
    any of them
}