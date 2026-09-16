rule TTP_XOR_WriteProcessMemory_d114 {
  strings:
    $key_d114 = { 86 66 [2] b4 44 [2] b2 71 [2] 9c 71 [2] a3 6d }

  condition:
    any of them
}