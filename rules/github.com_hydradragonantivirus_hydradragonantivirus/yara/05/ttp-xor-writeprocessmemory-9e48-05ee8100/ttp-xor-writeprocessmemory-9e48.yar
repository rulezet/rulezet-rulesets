rule TTP_XOR_WriteProcessMemory_9e48 {
  strings:
    $key_9e48 = { c9 3a [2] fb 18 [2] fd 2d [2] d3 2d [2] ec 31 }

  condition:
    any of them
}