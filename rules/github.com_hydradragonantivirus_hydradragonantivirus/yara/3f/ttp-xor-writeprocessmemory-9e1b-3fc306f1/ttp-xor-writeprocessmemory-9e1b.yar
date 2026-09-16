rule TTP_XOR_WriteProcessMemory_9e1b {
  strings:
    $key_9e1b = { c9 69 [2] fb 4b [2] fd 7e [2] d3 7e [2] ec 62 }

  condition:
    any of them
}