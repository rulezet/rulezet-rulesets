rule TTP_XOR_WriteProcessMemory_d314 {
  strings:
    $key_d314 = { 84 66 [2] b6 44 [2] b0 71 [2] 9e 71 [2] a1 6d }

  condition:
    any of them
}