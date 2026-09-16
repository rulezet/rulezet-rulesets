rule TTP_XOR_WriteProcessMemory_3f99 {
  strings:
    $key_3f99 = { 68 eb [2] 5a c9 [2] 5c fc [2] 72 fc [2] 4d e0 }

  condition:
    any of them
}