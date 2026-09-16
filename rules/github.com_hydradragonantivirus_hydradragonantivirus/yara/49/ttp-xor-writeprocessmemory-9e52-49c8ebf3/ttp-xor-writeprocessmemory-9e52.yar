rule TTP_XOR_WriteProcessMemory_9e52 {
  strings:
    $key_9e52 = { c9 20 [2] fb 02 [2] fd 37 [2] d3 37 [2] ec 2b }

  condition:
    any of them
}