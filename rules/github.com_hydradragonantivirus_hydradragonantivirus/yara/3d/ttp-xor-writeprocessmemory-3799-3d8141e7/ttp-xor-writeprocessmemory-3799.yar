rule TTP_XOR_WriteProcessMemory_3799 {
  strings:
    $key_3799 = { 60 eb [2] 52 c9 [2] 54 fc [2] 7a fc [2] 45 e0 }

  condition:
    any of them
}