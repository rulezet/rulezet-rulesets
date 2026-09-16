rule TTP_XOR_WriteProcessMemory_7399 {
  strings:
    $key_7399 = { 24 eb [2] 16 c9 [2] 10 fc [2] 3e fc [2] 01 e0 }

  condition:
    any of them
}