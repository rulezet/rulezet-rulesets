rule TTP_XOR_WriteProcessMemory_c173 {
  strings:
    $key_c173 = { 96 01 [2] a4 23 [2] a2 16 [2] 8c 16 [2] b3 0a }

  condition:
    any of them
}