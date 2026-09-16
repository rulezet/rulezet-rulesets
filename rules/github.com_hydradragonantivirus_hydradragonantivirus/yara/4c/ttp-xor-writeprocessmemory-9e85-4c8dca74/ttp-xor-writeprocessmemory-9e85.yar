rule TTP_XOR_WriteProcessMemory_9e85 {
  strings:
    $key_9e85 = { c9 f7 [2] fb d5 [2] fd e0 [2] d3 e0 [2] ec fc }

  condition:
    any of them
}