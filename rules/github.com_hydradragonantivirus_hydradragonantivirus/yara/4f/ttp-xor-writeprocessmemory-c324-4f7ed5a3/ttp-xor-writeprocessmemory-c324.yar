rule TTP_XOR_WriteProcessMemory_c324 {
  strings:
    $key_c324 = { 94 56 [2] a6 74 [2] a0 41 [2] 8e 41 [2] b1 5d }

  condition:
    any of them
}