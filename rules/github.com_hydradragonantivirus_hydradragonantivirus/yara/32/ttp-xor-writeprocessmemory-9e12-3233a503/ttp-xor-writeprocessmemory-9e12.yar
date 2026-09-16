rule TTP_XOR_WriteProcessMemory_9e12 {
  strings:
    $key_9e12 = { c9 60 [2] fb 42 [2] fd 77 [2] d3 77 [2] ec 6b }

  condition:
    any of them
}