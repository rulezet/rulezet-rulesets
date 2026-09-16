rule TTP_XOR_WriteProcessMemory_9e82 {
  strings:
    $key_9e82 = { c9 f0 [2] fb d2 [2] fd e7 [2] d3 e7 [2] ec fb }

  condition:
    any of them
}