rule TTP_XOR_WriteProcessMemory_0ee0 {
  strings:
    $key_0ee0 = { 59 92 [2] 6b b0 [2] 6d 85 [2] 43 85 [2] 7c 99 }

  condition:
    any of them
}