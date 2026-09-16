rule TTP_XOR_WriteProcessMemory_a699 {
  strings:
    $key_a699 = { f1 eb [2] c3 c9 [2] c5 fc [2] eb fc [2] d4 e0 }

  condition:
    any of them
}