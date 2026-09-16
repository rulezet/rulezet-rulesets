rule TTP_XOR_WriteProcessMemory_c177 {
  strings:
    $key_c177 = { 96 05 [2] a4 27 [2] a2 12 [2] 8c 12 [2] b3 0e }

  condition:
    any of them
}