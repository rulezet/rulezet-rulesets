rule TTP_XOR_WriteProcessMemory_d411 {
  strings:
    $key_d411 = { 83 63 [2] b1 41 [2] b7 74 [2] 99 74 [2] a6 68 }

  condition:
    any of them
}