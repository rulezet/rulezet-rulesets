rule TTP_XOR_WriteProcessMemory_9e68 {
  strings:
    $key_9e68 = { c9 1a [2] fb 38 [2] fd 0d [2] d3 0d [2] ec 11 }

  condition:
    any of them
}