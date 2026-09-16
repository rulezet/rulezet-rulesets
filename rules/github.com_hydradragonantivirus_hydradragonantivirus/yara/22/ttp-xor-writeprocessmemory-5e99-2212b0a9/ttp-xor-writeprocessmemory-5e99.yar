rule TTP_XOR_WriteProcessMemory_5e99 {
  strings:
    $key_5e99 = { 09 eb [2] 3b c9 [2] 3d fc [2] 13 fc [2] 2c e0 }

  condition:
    any of them
}