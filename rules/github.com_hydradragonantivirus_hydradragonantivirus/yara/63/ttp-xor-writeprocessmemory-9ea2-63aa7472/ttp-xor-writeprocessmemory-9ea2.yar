rule TTP_XOR_WriteProcessMemory_9ea2 {
  strings:
    $key_9ea2 = { c9 d0 [2] fb f2 [2] fd c7 [2] d3 c7 [2] ec db }

  condition:
    any of them
}