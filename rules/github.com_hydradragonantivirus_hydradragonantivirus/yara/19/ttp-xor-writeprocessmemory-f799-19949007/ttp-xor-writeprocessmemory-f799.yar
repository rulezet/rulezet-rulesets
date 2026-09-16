rule TTP_XOR_WriteProcessMemory_f799 {
  strings:
    $key_f799 = { a0 eb [2] 92 c9 [2] 94 fc [2] ba fc [2] 85 e0 }

  condition:
    any of them
}