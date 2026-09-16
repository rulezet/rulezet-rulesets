rule TTP_XOR_WriteProcessMemory_6999 {
  strings:
    $key_6999 = { 3e eb [2] 0c c9 [2] 0a fc [2] 24 fc [2] 1b e0 }

  condition:
    any of them
}