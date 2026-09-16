rule TTP_XOR_WriteProcessMemory_9ea4 {
  strings:
    $key_9ea4 = { c9 d6 [2] fb f4 [2] fd c1 [2] d3 c1 [2] ec dd }

  condition:
    any of them
}