rule TTP_XOR_WriteProcessMemory_d3ea {
  strings:
    $key_d3ea = { 84 98 [2] b6 ba [2] b0 8f [2] 9e 8f [2] a1 93 }

  condition:
    any of them
}