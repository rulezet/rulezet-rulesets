rule TTP_XOR_WriteProcessMemory_9e0b {
  strings:
    $key_9e0b = { c9 79 [2] fb 5b [2] fd 6e [2] d3 6e [2] ec 72 }

  condition:
    any of them
}