rule TTP_XOR_WriteProcessMemory_9e22 {
  strings:
    $key_9e22 = { c9 50 [2] fb 72 [2] fd 47 [2] d3 47 [2] ec 5b }

  condition:
    any of them
}