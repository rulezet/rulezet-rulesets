rule TTP_XOR_WriteProcessMemory_d364 {
  strings:
    $key_d364 = { 84 16 [2] b6 34 [2] b0 01 [2] 9e 01 [2] a1 1d }

  condition:
    any of them
}