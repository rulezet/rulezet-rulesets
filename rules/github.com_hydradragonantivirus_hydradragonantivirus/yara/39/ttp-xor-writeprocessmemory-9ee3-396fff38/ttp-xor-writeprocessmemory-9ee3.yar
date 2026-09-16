rule TTP_XOR_WriteProcessMemory_9ee3 {
  strings:
    $key_9ee3 = { c9 91 [2] fb b3 [2] fd 86 [2] d3 86 [2] ec 9a }

  condition:
    any of them
}