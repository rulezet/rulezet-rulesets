rule TTP_XOR_WriteProcessMemory_a399 {
  strings:
    $key_a399 = { f4 eb [2] c6 c9 [2] c0 fc [2] ee fc [2] d1 e0 }

  condition:
    any of them
}