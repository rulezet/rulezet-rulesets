rule TTP_XOR_WriteProcessMemory_9ee1 {
  strings:
    $key_9ee1 = { c9 93 [2] fb b1 [2] fd 84 [2] d3 84 [2] ec 98 }

  condition:
    any of them
}