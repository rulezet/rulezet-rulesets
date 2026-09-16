rule TTP_XOR_WriteProcessMemory_a68e {
  strings:
    $key_a68e = { f1 fc [2] c3 de [2] c5 eb [2] eb eb [2] d4 f7 }

  condition:
    any of them
}