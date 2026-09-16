rule TTP_XOR_WriteProcessMemory_9e10 {
  strings:
    $key_9e10 = { c9 62 [2] fb 40 [2] fd 75 [2] d3 75 [2] ec 69 }

  condition:
    any of them
}