rule TTP_XOR_WriteProcessMemory_6c99 {
  strings:
    $key_6c99 = { 3b eb [2] 09 c9 [2] 0f fc [2] 21 fc [2] 1e e0 }

  condition:
    any of them
}