rule TTP_XOR_WriteProcessMemory_9e32 {
  strings:
    $key_9e32 = { c9 40 [2] fb 62 [2] fd 57 [2] d3 57 [2] ec 4b }

  condition:
    any of them
}