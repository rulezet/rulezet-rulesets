rule TTP_XOR_WriteProcessMemory_d091 {
  strings:
    $key_d091 = { 87 e3 [2] b5 c1 [2] b3 f4 [2] 9d f4 [2] a2 e8 }

  condition:
    any of them
}