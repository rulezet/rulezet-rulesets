rule TTP_XOR_WriteProcessMemory_c414 {
  strings:
    $key_c414 = { 93 66 [2] a1 44 [2] a7 71 [2] 89 71 [2] b6 6d }

  condition:
    any of them
}