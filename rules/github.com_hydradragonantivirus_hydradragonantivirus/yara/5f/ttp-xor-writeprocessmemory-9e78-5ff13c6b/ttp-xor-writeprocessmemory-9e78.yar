rule TTP_XOR_WriteProcessMemory_9e78 {
  strings:
    $key_9e78 = { c9 0a [2] fb 28 [2] fd 1d [2] d3 1d [2] ec 01 }

  condition:
    any of them
}