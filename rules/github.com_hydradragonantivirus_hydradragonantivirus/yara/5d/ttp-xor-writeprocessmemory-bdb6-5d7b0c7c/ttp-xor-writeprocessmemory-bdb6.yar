rule TTP_XOR_WriteProcessMemory_bdb6 {
  strings:
    $key_bdb6 = { ea c4 [2] d8 e6 [2] de d3 [2] f0 d3 [2] cf cf }

  condition:
    any of them
}