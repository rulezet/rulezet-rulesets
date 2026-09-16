rule TTP_XOR_WriteProcessMemory_d354 {
  strings:
    $key_d354 = { 84 26 [2] b6 04 [2] b0 31 [2] 9e 31 [2] a1 2d }

  condition:
    any of them
}