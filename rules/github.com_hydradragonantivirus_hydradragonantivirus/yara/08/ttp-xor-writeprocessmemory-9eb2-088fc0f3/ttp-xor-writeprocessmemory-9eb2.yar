rule TTP_XOR_WriteProcessMemory_9eb2 {
  strings:
    $key_9eb2 = { c9 c0 [2] fb e2 [2] fd d7 [2] d3 d7 [2] ec cb }

  condition:
    any of them
}