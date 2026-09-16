rule TTP_XOR_WriteProcessMemory_7599 {
  strings:
    $key_7599 = { 22 eb [2] 10 c9 [2] 16 fc [2] 38 fc [2] 07 e0 }

  condition:
    any of them
}