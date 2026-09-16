rule TTP_XOR_WriteProcessMemory_27e0 {
  strings:
    $key_27e0 = { 70 92 [2] 42 b0 [2] 44 85 [2] 6a 85 [2] 55 99 }

  condition:
    any of them
}