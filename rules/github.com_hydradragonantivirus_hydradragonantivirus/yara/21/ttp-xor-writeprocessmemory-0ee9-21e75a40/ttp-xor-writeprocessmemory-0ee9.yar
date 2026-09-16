rule TTP_XOR_WriteProcessMemory_0ee9 {
  strings:
    $key_0ee9 = { 59 9b [2] 6b b9 [2] 6d 8c [2] 43 8c [2] 7c 90 }

  condition:
    any of them
}