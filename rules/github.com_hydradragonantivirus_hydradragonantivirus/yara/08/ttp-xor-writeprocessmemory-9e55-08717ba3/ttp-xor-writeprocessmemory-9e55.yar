rule TTP_XOR_WriteProcessMemory_9e55 {
  strings:
    $key_9e55 = { c9 27 [2] fb 05 [2] fd 30 [2] d3 30 [2] ec 2c }

  condition:
    any of them
}