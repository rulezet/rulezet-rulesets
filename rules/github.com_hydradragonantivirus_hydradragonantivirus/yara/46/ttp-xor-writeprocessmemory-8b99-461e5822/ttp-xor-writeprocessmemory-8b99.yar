rule TTP_XOR_WriteProcessMemory_8b99 {
  strings:
    $key_8b99 = { dc eb [2] ee c9 [2] e8 fc [2] c6 fc [2] f9 e0 }

  condition:
    any of them
}