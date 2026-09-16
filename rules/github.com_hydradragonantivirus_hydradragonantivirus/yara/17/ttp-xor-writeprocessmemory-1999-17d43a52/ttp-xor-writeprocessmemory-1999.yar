rule TTP_XOR_WriteProcessMemory_1999 {
  strings:
    $key_1999 = { 4e eb [2] 7c c9 [2] 7a fc [2] 54 fc [2] 6b e0 }

  condition:
    any of them
}