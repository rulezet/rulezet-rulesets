rule TTP_XOR_WriteProcessMemory_d214 {
  strings:
    $key_d214 = { 85 66 [2] b7 44 [2] b1 71 [2] 9f 71 [2] a0 6d }

  condition:
    any of them
}