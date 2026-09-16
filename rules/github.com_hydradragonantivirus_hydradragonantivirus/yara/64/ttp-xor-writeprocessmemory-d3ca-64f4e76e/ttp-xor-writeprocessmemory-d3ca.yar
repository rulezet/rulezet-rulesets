rule TTP_XOR_WriteProcessMemory_d3ca {
  strings:
    $key_d3ca = { 84 b8 [2] b6 9a [2] b0 af [2] 9e af [2] a1 b3 }

  condition:
    any of them
}