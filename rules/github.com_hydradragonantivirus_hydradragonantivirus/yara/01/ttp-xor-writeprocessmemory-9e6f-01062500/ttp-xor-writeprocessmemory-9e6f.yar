rule TTP_XOR_WriteProcessMemory_9e6f {
  strings:
    $key_9e6f = { c9 1d [2] fb 3f [2] fd 0a [2] d3 0a [2] ec 16 }

  condition:
    any of them
}