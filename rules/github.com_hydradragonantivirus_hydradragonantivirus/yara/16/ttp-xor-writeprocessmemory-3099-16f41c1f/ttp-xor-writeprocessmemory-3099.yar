rule TTP_XOR_WriteProcessMemory_3099 {
  strings:
    $key_3099 = { 67 eb [2] 55 c9 [2] 53 fc [2] 7d fc [2] 42 e0 }

  condition:
    any of them
}