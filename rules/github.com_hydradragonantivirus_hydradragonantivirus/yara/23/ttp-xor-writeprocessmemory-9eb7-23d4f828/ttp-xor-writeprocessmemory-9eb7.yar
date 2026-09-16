rule TTP_XOR_WriteProcessMemory_9eb7 {
  strings:
    $key_9eb7 = { c9 c5 [2] fb e7 [2] fd d2 [2] d3 d2 [2] ec ce }

  condition:
    any of them
}