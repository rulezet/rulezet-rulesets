rule TTP_XOR_WriteProcessMemory_c6d3 {
  strings:
    $key_c6d3 = { 91 a1 [2] a3 83 [2] a5 b6 [2] 8b b6 [2] b4 aa }

  condition:
    any of them
}