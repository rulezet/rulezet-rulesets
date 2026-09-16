rule TTP_XOR_WriteProcessMemory_9bbb {
  strings:
    $key_9bbb = { cc c9 [2] fe eb [2] f8 de [2] d6 de [2] e9 c2 }

  condition:
    any of them
}