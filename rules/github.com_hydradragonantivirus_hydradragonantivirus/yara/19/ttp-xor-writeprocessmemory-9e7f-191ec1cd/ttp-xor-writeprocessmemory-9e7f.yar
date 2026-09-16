rule TTP_XOR_WriteProcessMemory_9e7f {
  strings:
    $key_9e7f = { c9 0d [2] fb 2f [2] fd 1a [2] d3 1a [2] ec 06 }

  condition:
    any of them
}