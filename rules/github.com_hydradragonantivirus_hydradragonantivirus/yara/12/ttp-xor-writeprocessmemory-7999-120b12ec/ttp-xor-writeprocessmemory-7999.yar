rule TTP_XOR_WriteProcessMemory_7999 {
  strings:
    $key_7999 = { 2e eb [2] 1c c9 [2] 1a fc [2] 34 fc [2] 0b e0 }

  condition:
    any of them
}