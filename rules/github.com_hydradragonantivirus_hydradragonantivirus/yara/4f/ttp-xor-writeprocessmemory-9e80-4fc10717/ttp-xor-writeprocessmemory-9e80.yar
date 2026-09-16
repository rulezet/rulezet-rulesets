rule TTP_XOR_WriteProcessMemory_9e80 {
  strings:
    $key_9e80 = { c9 f2 [2] fb d0 [2] fd e5 [2] d3 e5 [2] ec f9 }

  condition:
    any of them
}