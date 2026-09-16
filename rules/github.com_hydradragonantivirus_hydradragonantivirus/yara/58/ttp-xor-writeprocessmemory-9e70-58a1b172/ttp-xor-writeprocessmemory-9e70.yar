rule TTP_XOR_WriteProcessMemory_9e70 {
  strings:
    $key_9e70 = { c9 02 [2] fb 20 [2] fd 15 [2] d3 15 [2] ec 09 }

  condition:
    any of them
}