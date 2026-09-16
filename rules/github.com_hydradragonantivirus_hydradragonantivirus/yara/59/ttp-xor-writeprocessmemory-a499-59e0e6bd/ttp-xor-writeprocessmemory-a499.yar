rule TTP_XOR_WriteProcessMemory_a499 {
  strings:
    $key_a499 = { f3 eb [2] c1 c9 [2] c7 fc [2] e9 fc [2] d6 e0 }

  condition:
    any of them
}