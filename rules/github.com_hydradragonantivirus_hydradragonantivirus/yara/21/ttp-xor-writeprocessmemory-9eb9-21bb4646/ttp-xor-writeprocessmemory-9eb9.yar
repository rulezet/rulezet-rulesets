rule TTP_XOR_WriteProcessMemory_9eb9 {
  strings:
    $key_9eb9 = { c9 cb [2] fb e9 [2] fd dc [2] d3 dc [2] ec c0 }

  condition:
    any of them
}