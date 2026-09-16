rule TTP_XOR_WriteProcessMemory_9e90 {
  strings:
    $key_9e90 = { c9 e2 [2] fb c0 [2] fd f5 [2] d3 f5 [2] ec e9 }

  condition:
    any of them
}