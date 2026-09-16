rule TTP_XOR_WriteProcessMemory_7f99 {
  strings:
    $key_7f99 = { 28 eb [2] 1a c9 [2] 1c fc [2] 32 fc [2] 0d e0 }

  condition:
    any of them
}