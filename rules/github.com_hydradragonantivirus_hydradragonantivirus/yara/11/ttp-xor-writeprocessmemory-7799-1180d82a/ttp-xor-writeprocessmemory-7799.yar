rule TTP_XOR_WriteProcessMemory_7799 {
  strings:
    $key_7799 = { 20 eb [2] 12 c9 [2] 14 fc [2] 3a fc [2] 05 e0 }

  condition:
    any of them
}