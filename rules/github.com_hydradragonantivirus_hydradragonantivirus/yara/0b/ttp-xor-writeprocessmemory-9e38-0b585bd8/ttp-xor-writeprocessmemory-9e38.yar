rule TTP_XOR_WriteProcessMemory_9e38 {
  strings:
    $key_9e38 = { c9 4a [2] fb 68 [2] fd 5d [2] d3 5d [2] ec 41 }

  condition:
    any of them
}