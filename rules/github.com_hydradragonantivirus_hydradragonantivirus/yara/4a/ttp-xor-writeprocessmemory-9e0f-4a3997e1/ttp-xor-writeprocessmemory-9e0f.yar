rule TTP_XOR_WriteProcessMemory_9e0f {
  strings:
    $key_9e0f = { c9 7d [2] fb 5f [2] fd 6a [2] d3 6a [2] ec 76 }

  condition:
    any of them
}