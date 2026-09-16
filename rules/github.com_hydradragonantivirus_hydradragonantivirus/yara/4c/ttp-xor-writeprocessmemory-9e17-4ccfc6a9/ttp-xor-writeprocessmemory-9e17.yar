rule TTP_XOR_WriteProcessMemory_9e17 {
  strings:
    $key_9e17 = { c9 65 [2] fb 47 [2] fd 72 [2] d3 72 [2] ec 6e }

  condition:
    any of them
}