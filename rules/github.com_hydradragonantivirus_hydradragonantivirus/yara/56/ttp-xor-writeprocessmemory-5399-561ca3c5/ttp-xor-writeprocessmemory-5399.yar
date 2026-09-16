rule TTP_XOR_WriteProcessMemory_5399 {
  strings:
    $key_5399 = { 04 eb [2] 36 c9 [2] 30 fc [2] 1e fc [2] 21 e0 }

  condition:
    any of them
}