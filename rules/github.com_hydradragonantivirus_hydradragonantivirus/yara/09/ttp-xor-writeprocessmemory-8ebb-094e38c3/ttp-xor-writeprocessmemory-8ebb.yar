rule TTP_XOR_WriteProcessMemory_8ebb {
  strings:
    $key_8ebb = { d9 c9 [2] eb eb [2] ed de [2] c3 de [2] fc c2 }

  condition:
    any of them
}