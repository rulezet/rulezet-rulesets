rule TTP_XOR_WriteProcessMemory_9e7c {
  strings:
    $key_9e7c = { c9 0e [2] fb 2c [2] fd 19 [2] d3 19 [2] ec 05 }

  condition:
    any of them
}