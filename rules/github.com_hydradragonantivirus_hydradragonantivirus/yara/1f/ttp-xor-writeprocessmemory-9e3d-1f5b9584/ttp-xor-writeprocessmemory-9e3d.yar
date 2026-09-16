rule TTP_XOR_WriteProcessMemory_9e3d {
  strings:
    $key_9e3d = { c9 4f [2] fb 6d [2] fd 58 [2] d3 58 [2] ec 44 }

  condition:
    any of them
}