rule TTP_XOR_WriteProcessMemory_8399 {
  strings:
    $key_8399 = { d4 eb [2] e6 c9 [2] e0 fc [2] ce fc [2] f1 e0 }

  condition:
    any of them
}