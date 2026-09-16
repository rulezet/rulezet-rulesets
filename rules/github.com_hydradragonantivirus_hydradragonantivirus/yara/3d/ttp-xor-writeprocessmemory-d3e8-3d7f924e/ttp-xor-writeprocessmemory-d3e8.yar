rule TTP_XOR_WriteProcessMemory_d3e8 {
  strings:
    $key_d3e8 = { 84 9a [2] b6 b8 [2] b0 8d [2] 9e 8d [2] a1 91 }

  condition:
    any of them
}