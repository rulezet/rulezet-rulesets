rule TTP_XOR_WriteProcessMemory_2999 {
  strings:
    $key_2999 = { 7e eb [2] 4c c9 [2] 4a fc [2] 64 fc [2] 5b e0 }

  condition:
    any of them
}