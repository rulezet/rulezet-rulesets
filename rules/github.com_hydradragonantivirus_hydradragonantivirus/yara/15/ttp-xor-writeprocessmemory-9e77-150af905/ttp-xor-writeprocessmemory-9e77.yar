rule TTP_XOR_WriteProcessMemory_9e77 {
  strings:
    $key_9e77 = { c9 05 [2] fb 27 [2] fd 12 [2] d3 12 [2] ec 0e }

  condition:
    any of them
}