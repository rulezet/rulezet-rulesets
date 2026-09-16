rule TTP_XOR_WriteProcessMemory_9e8a {
  strings:
    $key_9e8a = { c9 f8 [2] fb da [2] fd ef [2] d3 ef [2] ec f3 }

  condition:
    any of them
}