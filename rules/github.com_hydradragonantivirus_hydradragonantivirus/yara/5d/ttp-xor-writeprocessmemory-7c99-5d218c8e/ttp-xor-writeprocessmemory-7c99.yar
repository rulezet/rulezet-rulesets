rule TTP_XOR_WriteProcessMemory_7c99 {
  strings:
    $key_7c99 = { 2b eb [2] 19 c9 [2] 1f fc [2] 31 fc [2] 0e e0 }

  condition:
    any of them
}