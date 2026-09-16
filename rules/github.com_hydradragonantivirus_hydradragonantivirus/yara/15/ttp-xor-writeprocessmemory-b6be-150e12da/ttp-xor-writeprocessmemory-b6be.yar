rule TTP_XOR_WriteProcessMemory_b6be {
  strings:
    $key_b6be = { e1 cc [2] d3 ee [2] d5 db [2] fb db [2] c4 c7 }

  condition:
    any of them
}