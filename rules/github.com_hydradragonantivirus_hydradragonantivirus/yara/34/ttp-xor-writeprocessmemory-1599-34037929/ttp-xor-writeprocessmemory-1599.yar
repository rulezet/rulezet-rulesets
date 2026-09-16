rule TTP_XOR_WriteProcessMemory_1599 {
  strings:
    $key_1599 = { 42 eb [2] 70 c9 [2] 76 fc [2] 58 fc [2] 67 e0 }

  condition:
    any of them
}