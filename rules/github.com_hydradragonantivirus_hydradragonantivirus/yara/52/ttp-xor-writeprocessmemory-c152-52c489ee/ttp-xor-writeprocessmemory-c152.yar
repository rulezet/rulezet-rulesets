rule TTP_XOR_WriteProcessMemory_c152 {
  strings:
    $key_c152 = { 96 20 [2] a4 02 [2] a2 37 [2] 8c 37 [2] b3 2b }

  condition:
    any of them
}