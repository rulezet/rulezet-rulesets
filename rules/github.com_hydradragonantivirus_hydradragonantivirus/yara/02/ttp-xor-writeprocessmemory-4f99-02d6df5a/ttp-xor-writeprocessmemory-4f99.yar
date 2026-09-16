rule TTP_XOR_WriteProcessMemory_4f99 {
  strings:
    $key_4f99 = { 18 eb [2] 2a c9 [2] 2c fc [2] 02 fc [2] 3d e0 }

  condition:
    any of them
}