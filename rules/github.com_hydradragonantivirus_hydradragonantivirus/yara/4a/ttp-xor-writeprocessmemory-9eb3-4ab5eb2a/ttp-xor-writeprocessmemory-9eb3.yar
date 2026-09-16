rule TTP_XOR_WriteProcessMemory_9eb3 {
  strings:
    $key_9eb3 = { c9 c1 [2] fb e3 [2] fd d6 [2] d3 d6 [2] ec ca }

  condition:
    any of them
}