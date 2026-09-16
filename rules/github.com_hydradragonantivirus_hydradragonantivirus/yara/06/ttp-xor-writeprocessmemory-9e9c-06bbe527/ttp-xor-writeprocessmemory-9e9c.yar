rule TTP_XOR_WriteProcessMemory_9e9c {
  strings:
    $key_9e9c = { c9 ee [2] fb cc [2] fd f9 [2] d3 f9 [2] ec e5 }

  condition:
    any of them
}