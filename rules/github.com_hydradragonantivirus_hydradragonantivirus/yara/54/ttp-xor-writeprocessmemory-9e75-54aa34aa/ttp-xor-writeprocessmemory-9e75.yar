rule TTP_XOR_WriteProcessMemory_9e75 {
  strings:
    $key_9e75 = { c9 07 [2] fb 25 [2] fd 10 [2] d3 10 [2] ec 0c }

  condition:
    any of them
}