rule TTP_XOR_WriteProcessMemory_1c99 {
  strings:
    $key_1c99 = { 4b eb [2] 79 c9 [2] 7f fc [2] 51 fc [2] 6e e0 }

  condition:
    any of them
}