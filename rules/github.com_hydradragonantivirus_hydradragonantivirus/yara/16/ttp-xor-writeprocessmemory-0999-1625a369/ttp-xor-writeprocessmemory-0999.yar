rule TTP_XOR_WriteProcessMemory_0999 {
  strings:
    $key_0999 = { 5e eb [2] 6c c9 [2] 6a fc [2] 44 fc [2] 7b e0 }

  condition:
    any of them
}