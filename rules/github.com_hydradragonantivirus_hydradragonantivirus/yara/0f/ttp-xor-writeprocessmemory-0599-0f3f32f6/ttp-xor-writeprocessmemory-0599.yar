rule TTP_XOR_WriteProcessMemory_0599 {
  strings:
    $key_0599 = { 52 eb [2] 60 c9 [2] 66 fc [2] 48 fc [2] 77 e0 }

  condition:
    any of them
}