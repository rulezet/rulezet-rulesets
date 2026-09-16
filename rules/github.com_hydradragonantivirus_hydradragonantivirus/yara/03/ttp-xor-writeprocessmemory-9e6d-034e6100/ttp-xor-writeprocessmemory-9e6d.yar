rule TTP_XOR_WriteProcessMemory_9e6d {
  strings:
    $key_9e6d = { c9 1f [2] fb 3d [2] fd 08 [2] d3 08 [2] ec 14 }

  condition:
    any of them
}