rule TTP_XOR_WriteProcessMemory_9e57 {
  strings:
    $key_9e57 = { c9 25 [2] fb 07 [2] fd 32 [2] d3 32 [2] ec 2e }

  condition:
    any of them
}