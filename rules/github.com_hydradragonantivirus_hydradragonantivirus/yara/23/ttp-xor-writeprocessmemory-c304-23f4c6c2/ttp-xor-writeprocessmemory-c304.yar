rule TTP_XOR_WriteProcessMemory_c304 {
  strings:
    $key_c304 = { 94 76 [2] a6 54 [2] a0 61 [2] 8e 61 [2] b1 7d }

  condition:
    any of them
}