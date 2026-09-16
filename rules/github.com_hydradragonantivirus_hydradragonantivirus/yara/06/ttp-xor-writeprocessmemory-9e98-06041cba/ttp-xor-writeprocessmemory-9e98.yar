rule TTP_XOR_WriteProcessMemory_9e98 {
  strings:
    $key_9e98 = { c9 ea [2] fb c8 [2] fd fd [2] d3 fd [2] ec e1 }

  condition:
    any of them
}