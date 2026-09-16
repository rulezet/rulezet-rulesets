rule TTP_XOR_WriteProcessMemory_9e96 {
  strings:
    $key_9e96 = { c9 e4 [2] fb c6 [2] fd f3 [2] d3 f3 [2] ec ef }

  condition:
    any of them
}