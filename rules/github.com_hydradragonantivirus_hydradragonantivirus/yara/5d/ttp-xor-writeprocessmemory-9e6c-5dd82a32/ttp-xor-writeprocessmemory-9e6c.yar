rule TTP_XOR_WriteProcessMemory_9e6c {
  strings:
    $key_9e6c = { c9 1e [2] fb 3c [2] fd 09 [2] d3 09 [2] ec 15 }

  condition:
    any of them
}