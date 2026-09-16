rule TTP_XOR_WriteProcessMemory_0ee7 {
  strings:
    $key_0ee7 = { 59 95 [2] 6b b7 [2] 6d 82 [2] 43 82 [2] 7c 9e }

  condition:
    any of them
}