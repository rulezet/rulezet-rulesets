rule TTP_XOR_WriteProcessMemory_9e92 {
  strings:
    $key_9e92 = { c9 e0 [2] fb c2 [2] fd f7 [2] d3 f7 [2] ec eb }

  condition:
    any of them
}