rule TTP_XOR_WriteProcessMemory_d899 {
  strings:
    $key_d899 = { 8f eb [2] bd c9 [2] bb fc [2] 95 fc [2] aa e0 }

  condition:
    any of them
}