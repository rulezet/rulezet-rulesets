rule TTP_XOR_WriteProcessMemory_d254 {
  strings:
    $key_d254 = { 85 26 [2] b7 04 [2] b1 31 [2] 9f 31 [2] a0 2d }

  condition:
    any of them
}