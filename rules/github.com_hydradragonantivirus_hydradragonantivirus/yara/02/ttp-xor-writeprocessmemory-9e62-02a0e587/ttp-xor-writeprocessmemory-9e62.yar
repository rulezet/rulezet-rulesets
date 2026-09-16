rule TTP_XOR_WriteProcessMemory_9e62 {
  strings:
    $key_9e62 = { c9 10 [2] fb 32 [2] fd 07 [2] d3 07 [2] ec 1b }

  condition:
    any of them
}