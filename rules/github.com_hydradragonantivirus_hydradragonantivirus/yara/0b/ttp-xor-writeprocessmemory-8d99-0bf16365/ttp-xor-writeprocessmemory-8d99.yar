rule TTP_XOR_WriteProcessMemory_8d99 {
  strings:
    $key_8d99 = { da eb [2] e8 c9 [2] ee fc [2] c0 fc [2] ff e0 }

  condition:
    any of them
}