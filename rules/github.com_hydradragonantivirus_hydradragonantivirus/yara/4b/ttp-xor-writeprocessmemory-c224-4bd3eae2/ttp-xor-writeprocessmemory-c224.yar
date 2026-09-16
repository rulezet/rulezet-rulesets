rule TTP_XOR_WriteProcessMemory_c224 {
  strings:
    $key_c224 = { 95 56 [2] a7 74 [2] a1 41 [2] 8f 41 [2] b0 5d }

  condition:
    any of them
}