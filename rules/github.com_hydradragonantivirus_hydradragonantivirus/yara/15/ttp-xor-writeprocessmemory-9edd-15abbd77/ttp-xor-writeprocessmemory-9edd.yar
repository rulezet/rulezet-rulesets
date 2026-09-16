rule TTP_XOR_WriteProcessMemory_9edd {
  strings:
    $key_9edd = { c9 af [2] fb 8d [2] fd b8 [2] d3 b8 [2] ec a4 }

  condition:
    any of them
}