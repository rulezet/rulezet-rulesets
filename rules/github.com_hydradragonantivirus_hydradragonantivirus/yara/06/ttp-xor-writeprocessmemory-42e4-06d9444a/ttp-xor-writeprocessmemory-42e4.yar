rule TTP_XOR_WriteProcessMemory_42e4 {
  strings:
    $key_42e4 = { 15 96 [2] 27 b4 [2] 21 81 [2] 0f 81 [2] 30 9d }

  condition:
    any of them
}