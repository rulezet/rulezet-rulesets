rule TTP_XOR_WriteProcessMemory_d464 {
  strings:
    $key_d464 = { 83 16 [2] b1 34 [2] b7 01 [2] 99 01 [2] a6 1d }

  condition:
    any of them
}