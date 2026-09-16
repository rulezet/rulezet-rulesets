rule TTP_XOR_WriteProcessMemory_fbb6 {
  strings:
    $key_fbb6 = { ac c4 [2] 9e e6 [2] 98 d3 [2] b6 d3 [2] 89 cf }

  condition:
    any of them
}