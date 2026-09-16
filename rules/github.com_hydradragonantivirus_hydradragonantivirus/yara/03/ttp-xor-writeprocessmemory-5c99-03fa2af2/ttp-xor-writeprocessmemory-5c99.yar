rule TTP_XOR_WriteProcessMemory_5c99 {
  strings:
    $key_5c99 = { 0b eb [2] 39 c9 [2] 3f fc [2] 11 fc [2] 2e e0 }

  condition:
    any of them
}