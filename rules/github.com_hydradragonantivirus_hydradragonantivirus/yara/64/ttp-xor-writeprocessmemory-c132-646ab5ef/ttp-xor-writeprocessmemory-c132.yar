rule TTP_XOR_WriteProcessMemory_c132 {
  strings:
    $key_c132 = { 96 40 [2] a4 62 [2] a2 57 [2] 8c 57 [2] b3 4b }

  condition:
    any of them
}