rule TTP_XOR_WriteProcessMemory_9ebb {
  strings:
    $key_9ebb = { c9 c9 [2] fb eb [2] fd de [2] d3 de [2] ec c2 }

  condition:
    any of them
}