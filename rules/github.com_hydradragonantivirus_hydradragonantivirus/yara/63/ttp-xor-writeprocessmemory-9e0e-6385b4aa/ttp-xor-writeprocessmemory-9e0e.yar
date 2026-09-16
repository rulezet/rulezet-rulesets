rule TTP_XOR_WriteProcessMemory_9e0e {
  strings:
    $key_9e0e = { c9 7c [2] fb 5e [2] fd 6b [2] d3 6b [2] ec 77 }

  condition:
    any of them
}