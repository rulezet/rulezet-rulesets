rule TTP_XOR_WriteProcessMemory_848e {
  strings:
    $key_848e = { d3 fc [2] e1 de [2] e7 eb [2] c9 eb [2] f6 f7 }

  condition:
    any of them
}