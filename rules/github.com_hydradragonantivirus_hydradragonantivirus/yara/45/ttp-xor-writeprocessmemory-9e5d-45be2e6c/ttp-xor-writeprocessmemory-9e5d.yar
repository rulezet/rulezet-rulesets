rule TTP_XOR_WriteProcessMemory_9e5d {
  strings:
    $key_9e5d = { c9 2f [2] fb 0d [2] fd 38 [2] d3 38 [2] ec 24 }

  condition:
    any of them
}