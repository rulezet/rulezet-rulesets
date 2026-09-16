rule TTP_XOR_WriteProcessMemory_5f99 {
  strings:
    $key_5f99 = { 08 eb [2] 3a c9 [2] 3c fc [2] 12 fc [2] 2d e0 }

  condition:
    any of them
}