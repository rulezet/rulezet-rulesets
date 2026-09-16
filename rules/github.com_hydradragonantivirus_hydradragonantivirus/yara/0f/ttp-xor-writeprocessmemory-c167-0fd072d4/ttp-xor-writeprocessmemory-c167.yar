rule TTP_XOR_WriteProcessMemory_c167 {
  strings:
    $key_c167 = { 96 15 [2] a4 37 [2] a2 02 [2] 8c 02 [2] b3 1e }

  condition:
    any of them
}