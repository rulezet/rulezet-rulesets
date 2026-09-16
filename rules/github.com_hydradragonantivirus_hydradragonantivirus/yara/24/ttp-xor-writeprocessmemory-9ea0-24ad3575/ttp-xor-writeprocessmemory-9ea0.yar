rule TTP_XOR_WriteProcessMemory_9ea0 {
  strings:
    $key_9ea0 = { c9 d2 [2] fb f0 [2] fd c5 [2] d3 c5 [2] ec d9 }

  condition:
    any of them
}