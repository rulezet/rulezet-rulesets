rule TTP_XOR_WriteProcessMemory_1799 {
  strings:
    $key_1799 = { 40 eb [2] 72 c9 [2] 74 fc [2] 5a fc [2] 65 e0 }

  condition:
    any of them
}