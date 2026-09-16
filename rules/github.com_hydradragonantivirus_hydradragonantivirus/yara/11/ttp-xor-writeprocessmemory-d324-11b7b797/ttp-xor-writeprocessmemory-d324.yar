rule TTP_XOR_WriteProcessMemory_d324 {
  strings:
    $key_d324 = { 84 56 [2] b6 74 [2] b0 41 [2] 9e 41 [2] a1 5d }

  condition:
    any of them
}