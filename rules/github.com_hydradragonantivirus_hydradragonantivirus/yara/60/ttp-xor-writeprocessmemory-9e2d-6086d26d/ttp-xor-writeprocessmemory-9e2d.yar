rule TTP_XOR_WriteProcessMemory_9e2d {
  strings:
    $key_9e2d = { c9 5f [2] fb 7d [2] fd 48 [2] d3 48 [2] ec 54 }

  condition:
    any of them
}