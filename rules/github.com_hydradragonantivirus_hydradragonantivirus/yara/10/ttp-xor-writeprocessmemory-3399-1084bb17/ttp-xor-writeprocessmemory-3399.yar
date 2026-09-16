rule TTP_XOR_WriteProcessMemory_3399 {
  strings:
    $key_3399 = { 64 eb [2] 56 c9 [2] 50 fc [2] 7e fc [2] 41 e0 }

  condition:
    any of them
}