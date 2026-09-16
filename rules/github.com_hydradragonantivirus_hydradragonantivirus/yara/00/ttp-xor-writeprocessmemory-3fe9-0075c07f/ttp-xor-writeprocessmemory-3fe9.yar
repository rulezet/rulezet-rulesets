rule TTP_XOR_WriteProcessMemory_3fe9 {
  strings:
    $key_3fe9 = { 68 9b [2] 5a b9 [2] 5c 8c [2] 72 8c [2] 4d 90 }

  condition:
    any of them
}