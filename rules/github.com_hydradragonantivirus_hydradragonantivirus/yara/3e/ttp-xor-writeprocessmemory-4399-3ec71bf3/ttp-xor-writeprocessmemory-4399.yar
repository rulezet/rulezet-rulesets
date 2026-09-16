rule TTP_XOR_WriteProcessMemory_4399 {
  strings:
    $key_4399 = { 14 eb [2] 26 c9 [2] 20 fc [2] 0e fc [2] 31 e0 }

  condition:
    any of them
}