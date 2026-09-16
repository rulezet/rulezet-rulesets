rule TTP_XOR_WriteProcessMemory_0ee3 {
  strings:
    $key_0ee3 = { 59 91 [2] 6b b3 [2] 6d 86 [2] 43 86 [2] 7c 9a }

  condition:
    any of them
}