rule TTP_XOR_WriteProcessMemory_9e58 {
  strings:
    $key_9e58 = { c9 2a [2] fb 08 [2] fd 3d [2] d3 3d [2] ec 21 }

  condition:
    any of them
}