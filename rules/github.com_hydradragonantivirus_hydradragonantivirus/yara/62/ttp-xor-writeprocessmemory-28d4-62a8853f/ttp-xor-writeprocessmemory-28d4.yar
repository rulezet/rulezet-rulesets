rule TTP_XOR_WriteProcessMemory_28d4 {
  strings:
    $key_28d4 = { 7f a6 [2] 4d 84 [2] 4b b1 [2] 65 b1 [2] 5a ad }

  condition:
    any of them
}