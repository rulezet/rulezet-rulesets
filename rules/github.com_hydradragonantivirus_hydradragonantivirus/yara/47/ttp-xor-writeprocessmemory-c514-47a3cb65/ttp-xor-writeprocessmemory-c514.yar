rule TTP_XOR_WriteProcessMemory_c514 {
  strings:
    $key_c514 = { 92 66 [2] a0 44 [2] a6 71 [2] 88 71 [2] b7 6d }

  condition:
    any of them
}