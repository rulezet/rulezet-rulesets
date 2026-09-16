rule TTP_XOR_WriteProcessMemory_28d7 {
  strings:
    $key_28d7 = { 7f a5 [2] 4d 87 [2] 4b b2 [2] 65 b2 [2] 5a ae }

  condition:
    any of them
}