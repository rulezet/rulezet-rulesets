rule TTP_XOR_WriteProcessMemory_9e4e {
  strings:
    $key_9e4e = { c9 3c [2] fb 1e [2] fd 2b [2] d3 2b [2] ec 37 }

  condition:
    any of them
}