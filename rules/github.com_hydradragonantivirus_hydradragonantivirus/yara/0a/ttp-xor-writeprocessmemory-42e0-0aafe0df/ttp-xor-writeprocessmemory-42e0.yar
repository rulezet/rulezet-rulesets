rule TTP_XOR_WriteProcessMemory_42e0 {
  strings:
    $key_42e0 = { 15 92 [2] 27 b0 [2] 21 85 [2] 0f 85 [2] 30 99 }

  condition:
    any of them
}