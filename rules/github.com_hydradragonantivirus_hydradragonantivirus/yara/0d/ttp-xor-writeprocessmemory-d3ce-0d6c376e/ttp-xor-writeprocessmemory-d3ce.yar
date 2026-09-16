rule TTP_XOR_WriteProcessMemory_d3ce {
  strings:
    $key_d3ce = { 84 bc [2] b6 9e [2] b0 ab [2] 9e ab [2] a1 b7 }

  condition:
    any of them
}