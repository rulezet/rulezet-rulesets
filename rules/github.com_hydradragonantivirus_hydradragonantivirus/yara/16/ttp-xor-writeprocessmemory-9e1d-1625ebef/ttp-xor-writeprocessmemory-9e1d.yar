rule TTP_XOR_WriteProcessMemory_9e1d {
  strings:
    $key_9e1d = { c9 6f [2] fb 4d [2] fd 78 [2] d3 78 [2] ec 64 }

  condition:
    any of them
}