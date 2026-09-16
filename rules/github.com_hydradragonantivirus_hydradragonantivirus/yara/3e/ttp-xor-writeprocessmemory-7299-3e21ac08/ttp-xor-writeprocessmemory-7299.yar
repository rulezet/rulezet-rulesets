rule TTP_XOR_WriteProcessMemory_7299 {
  strings:
    $key_7299 = { 25 eb [2] 17 c9 [2] 11 fc [2] 3f fc [2] 00 e0 }

  condition:
    any of them
}