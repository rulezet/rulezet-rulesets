rule TTP_XOR_WriteProcessMemory_d403 {
  strings:
    $key_d403 = { 83 71 [2] b1 53 [2] b7 66 [2] 99 66 [2] a6 7a }

  condition:
    any of them
}