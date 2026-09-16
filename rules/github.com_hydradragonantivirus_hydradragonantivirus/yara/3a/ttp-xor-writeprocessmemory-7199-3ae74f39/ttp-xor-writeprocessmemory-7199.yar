rule TTP_XOR_WriteProcessMemory_7199 {
  strings:
    $key_7199 = { 26 eb [2] 14 c9 [2] 12 fc [2] 3c fc [2] 03 e0 }

  condition:
    any of them
}