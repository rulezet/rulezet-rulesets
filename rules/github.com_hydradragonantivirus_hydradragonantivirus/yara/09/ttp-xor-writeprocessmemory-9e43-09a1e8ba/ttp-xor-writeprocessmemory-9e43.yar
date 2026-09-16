rule TTP_XOR_WriteProcessMemory_9e43 {
  strings:
    $key_9e43 = { c9 31 [2] fb 13 [2] fd 26 [2] d3 26 [2] ec 3a }

  condition:
    any of them
}