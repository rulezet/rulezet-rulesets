rule TTP_XOR_WriteProcessMemory_9399 {
  strings:
    $key_9399 = { c4 eb [2] f6 c9 [2] f0 fc [2] de fc [2] e1 e0 }

  condition:
    any of them
}