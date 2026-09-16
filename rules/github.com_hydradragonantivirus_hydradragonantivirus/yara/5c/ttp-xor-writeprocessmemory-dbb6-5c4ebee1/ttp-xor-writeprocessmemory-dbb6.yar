rule TTP_XOR_WriteProcessMemory_dbb6 {
  strings:
    $key_dbb6 = { 8c c4 [2] be e6 [2] b8 d3 [2] 96 d3 [2] a9 cf }

  condition:
    any of them
}