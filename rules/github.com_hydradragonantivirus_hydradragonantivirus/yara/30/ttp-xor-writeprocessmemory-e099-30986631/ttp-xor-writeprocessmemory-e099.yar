rule TTP_XOR_WriteProcessMemory_e099 {
  strings:
    $key_e099 = { b7 eb [2] 85 c9 [2] 83 fc [2] ad fc [2] 92 e0 }

  condition:
    any of them
}