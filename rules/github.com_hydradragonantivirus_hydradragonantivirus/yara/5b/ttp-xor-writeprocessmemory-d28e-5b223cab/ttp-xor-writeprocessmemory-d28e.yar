rule TTP_XOR_WriteProcessMemory_d28e {
  strings:
    $key_d28e = { 85 fc [2] b7 de [2] b1 eb [2] 9f eb [2] a0 f7 }

  condition:
    any of them
}