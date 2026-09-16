rule TTP_XOR_WriteProcessMemory_28d6 {
  strings:
    $key_28d6 = { 7f a4 [2] 4d 86 [2] 4b b3 [2] 65 b3 [2] 5a af }

  condition:
    any of them
}