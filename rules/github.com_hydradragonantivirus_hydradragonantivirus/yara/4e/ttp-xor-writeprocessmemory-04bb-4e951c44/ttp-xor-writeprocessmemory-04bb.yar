rule TTP_XOR_WriteProcessMemory_04bb {
  strings:
    $key_04bb = { 53 c9 [2] 61 eb [2] 67 de [2] 49 de [2] 76 c2 }

  condition:
    any of them
}