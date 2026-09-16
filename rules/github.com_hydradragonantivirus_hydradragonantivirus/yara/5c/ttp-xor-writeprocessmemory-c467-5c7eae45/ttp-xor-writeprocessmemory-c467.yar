rule TTP_XOR_WriteProcessMemory_c467 {
  strings:
    $key_c467 = { 93 15 [2] a1 37 [2] a7 02 [2] 89 02 [2] b6 1e }

  condition:
    any of them
}