rule TTP_XOR_WriteProcessMemory_f099 {
  strings:
    $key_f099 = { a7 eb [2] 95 c9 [2] 93 fc [2] bd fc [2] 82 e0 }

  condition:
    any of them
}