rule TTP_XOR_WriteProcessMemory_c511 {
  strings:
    $key_c511 = { 92 63 [2] a0 41 [2] a6 74 [2] 88 74 [2] b7 68 }

  condition:
    any of them
}