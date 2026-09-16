rule TTP_XOR_WriteProcessMemory_c424 {
  strings:
    $key_c424 = { 93 56 [2] a1 74 [2] a7 41 [2] 89 41 [2] b6 5d }

  condition:
    any of them
}