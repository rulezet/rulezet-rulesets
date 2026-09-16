rule TTP_XOR_WriteProcessMemory_5299 {
  strings:
    $key_5299 = { 05 eb [2] 37 c9 [2] 31 fc [2] 1f fc [2] 20 e0 }

  condition:
    any of them
}