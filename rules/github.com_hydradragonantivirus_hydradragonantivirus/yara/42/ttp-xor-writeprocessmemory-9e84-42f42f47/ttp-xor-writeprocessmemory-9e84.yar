rule TTP_XOR_WriteProcessMemory_9e84 {
  strings:
    $key_9e84 = { c9 f6 [2] fb d4 [2] fd e1 [2] d3 e1 [2] ec fd }

  condition:
    any of them
}