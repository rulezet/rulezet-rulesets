rule TTP_XOR_WriteProcessMemory_4899 {
  strings:
    $key_4899 = { 1f eb [2] 2d c9 [2] 2b fc [2] 05 fc [2] 3a e0 }

  condition:
    any of them
}