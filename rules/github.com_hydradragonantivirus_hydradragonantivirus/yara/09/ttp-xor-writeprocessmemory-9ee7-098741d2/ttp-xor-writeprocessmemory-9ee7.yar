rule TTP_XOR_WriteProcessMemory_9ee7 {
  strings:
    $key_9ee7 = { c9 95 [2] fb b7 [2] fd 82 [2] d3 82 [2] ec 9e }

  condition:
    any of them
}