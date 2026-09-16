rule TTP_XOR_WriteProcessMemory_9ed4 {
  strings:
    $key_9ed4 = { c9 a6 [2] fb 84 [2] fd b1 [2] d3 b1 [2] ec ad }

  condition:
    any of them
}