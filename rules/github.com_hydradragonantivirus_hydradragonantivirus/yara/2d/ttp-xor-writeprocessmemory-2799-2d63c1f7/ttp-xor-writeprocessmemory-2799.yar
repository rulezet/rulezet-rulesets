rule TTP_XOR_WriteProcessMemory_2799 {
  strings:
    $key_2799 = { 70 eb [2] 42 c9 [2] 44 fc [2] 6a fc [2] 55 e0 }

  condition:
    any of them
}