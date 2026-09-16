rule TTP_XOR_WriteProcessMemory_8499 {
  strings:
    $key_8499 = { d3 eb [2] e1 c9 [2] e7 fc [2] c9 fc [2] f6 e0 }

  condition:
    any of them
}