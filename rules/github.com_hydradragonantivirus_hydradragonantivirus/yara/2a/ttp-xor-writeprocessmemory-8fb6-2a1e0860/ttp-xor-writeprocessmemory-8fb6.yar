rule TTP_XOR_WriteProcessMemory_8fb6 {
  strings:
    $key_8fb6 = { d8 c4 [2] ea e6 [2] ec d3 [2] c2 d3 [2] fd cf }

  condition:
    any of them
}