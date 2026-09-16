rule TTP_XOR_WriteProcessMemory_d303 {
  strings:
    $key_d303 = { 84 71 [2] b6 53 [2] b0 66 [2] 9e 66 [2] a1 7a }

  condition:
    any of them
}