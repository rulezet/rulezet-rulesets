rule TTP_XOR_WriteProcessMemory_bab6 {
  strings:
    $key_bab6 = { ed c4 [2] df e6 [2] d9 d3 [2] f7 d3 [2] c8 cf }

  condition:
    any of them
}