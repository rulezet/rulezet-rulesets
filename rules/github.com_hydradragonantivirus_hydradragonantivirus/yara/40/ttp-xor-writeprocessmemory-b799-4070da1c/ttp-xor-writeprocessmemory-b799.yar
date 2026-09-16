rule TTP_XOR_WriteProcessMemory_b799 {
  strings:
    $key_b799 = { e0 eb [2] d2 c9 [2] d4 fc [2] fa fc [2] c5 e0 }

  condition:
    any of them
}