rule TTP_XOR_WriteProcessMemory_d323 {
  strings:
    $key_d323 = { 84 51 [2] b6 73 [2] b0 46 [2] 9e 46 [2] a1 5a }

  condition:
    any of them
}