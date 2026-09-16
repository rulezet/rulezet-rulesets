rule TTP_XOR_WriteProcessMemory_1299 {
  strings:
    $key_1299 = { 45 eb [2] 77 c9 [2] 71 fc [2] 5f fc [2] 60 e0 }

  condition:
    any of them
}