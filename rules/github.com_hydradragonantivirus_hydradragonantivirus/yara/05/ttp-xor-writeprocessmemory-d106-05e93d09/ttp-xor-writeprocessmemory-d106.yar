rule TTP_XOR_WriteProcessMemory_d106 {
  strings:
    $key_d106 = { 86 74 [2] b4 56 [2] b2 63 [2] 9c 63 [2] a3 7f }

  condition:
    any of them
}