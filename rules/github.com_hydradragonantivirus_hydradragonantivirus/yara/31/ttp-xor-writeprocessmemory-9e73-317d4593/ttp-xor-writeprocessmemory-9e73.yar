rule TTP_XOR_WriteProcessMemory_9e73 {
  strings:
    $key_9e73 = { c9 01 [2] fb 23 [2] fd 16 [2] d3 16 [2] ec 0a }

  condition:
    any of them
}