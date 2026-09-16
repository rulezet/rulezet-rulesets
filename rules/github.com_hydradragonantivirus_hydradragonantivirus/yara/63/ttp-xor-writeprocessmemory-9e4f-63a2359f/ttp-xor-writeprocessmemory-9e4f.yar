rule TTP_XOR_WriteProcessMemory_9e4f {
  strings:
    $key_9e4f = { c9 3d [2] fb 1f [2] fd 2a [2] d3 2a [2] ec 36 }

  condition:
    any of them
}