rule TTP_XOR_WriteProcessMemory_9eb5 {
  strings:
    $key_9eb5 = { c9 c7 [2] fb e5 [2] fd d0 [2] d3 d0 [2] ec cc }

  condition:
    any of them
}