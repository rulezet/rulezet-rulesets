rule TTP_XOR_WriteProcessMemory_c714 {
  strings:
    $key_c714 = { 90 66 [2] a2 44 [2] a4 71 [2] 8a 71 [2] b5 6d }

  condition:
    any of them
}