rule TTP_XOR_WriteProcessMemory_3899 {
  strings:
    $key_3899 = { 6f eb [2] 5d c9 [2] 5b fc [2] 75 fc [2] 4a e0 }

  condition:
    any of them
}