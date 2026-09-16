rule TTP_XOR_WriteProcessMemory_de99 {
  strings:
    $key_de99 = { 89 eb [2] bb c9 [2] bd fc [2] 93 fc [2] ac e0 }

  condition:
    any of them
}