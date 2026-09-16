rule TTP_XOR_WriteProcessMemory_9e81 {
  strings:
    $key_9e81 = { c9 f3 [2] fb d1 [2] fd e4 [2] d3 e4 [2] ec f8 }

  condition:
    any of them
}