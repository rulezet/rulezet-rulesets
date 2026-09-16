rule TTP_XOR_WriteProcessMemory_c143 {
  strings:
    $key_c143 = { 96 31 [2] a4 13 [2] a2 26 [2] 8c 26 [2] b3 3a }

  condition:
    any of them
}