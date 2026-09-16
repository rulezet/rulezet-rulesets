rule TTP_XOR_WriteProcessMemory_d2e3 {
  strings:
    $key_d2e3 = { 85 91 [2] b7 b3 [2] b1 86 [2] 9f 86 [2] a0 9a }

  condition:
    any of them
}