rule TTP_XOR_WriteProcessMemory_42e7 {
  strings:
    $key_42e7 = { 15 95 [2] 27 b7 [2] 21 82 [2] 0f 82 [2] 30 9e }

  condition:
    any of them
}