rule TTP_XOR_WriteProcessMemory_28d5 {
  strings:
    $key_28d5 = { 7f a7 [2] 4d 85 [2] 4b b0 [2] 65 b0 [2] 5a ac }

  condition:
    any of them
}