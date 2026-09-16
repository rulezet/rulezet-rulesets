rule TTP_XOR_WriteProcessMemory_9e41 {
  strings:
    $key_9e41 = { c9 33 [2] fb 11 [2] fd 24 [2] d3 24 [2] ec 38 }

  condition:
    any of them
}