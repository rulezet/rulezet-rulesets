rule TTP_XOR_WriteProcessMemory_6299 {
  strings:
    $key_6299 = { 35 eb [2] 07 c9 [2] 01 fc [2] 2f fc [2] 10 e0 }

  condition:
    any of them
}