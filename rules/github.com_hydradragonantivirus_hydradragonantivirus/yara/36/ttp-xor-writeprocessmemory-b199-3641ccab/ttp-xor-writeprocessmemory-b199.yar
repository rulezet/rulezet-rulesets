rule TTP_XOR_WriteProcessMemory_b199 {
  strings:
    $key_b199 = { e6 eb [2] d4 c9 [2] d2 fc [2] fc fc [2] c3 e0 }

  condition:
    any of them
}