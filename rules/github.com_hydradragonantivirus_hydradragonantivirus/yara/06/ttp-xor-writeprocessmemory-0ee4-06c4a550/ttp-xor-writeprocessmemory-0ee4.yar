rule TTP_XOR_WriteProcessMemory_0ee4 {
  strings:
    $key_0ee4 = { 59 96 [2] 6b b4 [2] 6d 81 [2] 43 81 [2] 7c 9d }

  condition:
    any of them
}