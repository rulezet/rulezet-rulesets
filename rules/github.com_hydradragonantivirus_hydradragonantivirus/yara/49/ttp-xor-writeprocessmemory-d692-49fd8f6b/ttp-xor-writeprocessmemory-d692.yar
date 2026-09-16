rule TTP_XOR_WriteProcessMemory_d692 {
  strings:
    $key_d692 = { 81 e0 [2] b3 c2 [2] b5 f7 [2] 9b f7 [2] a4 eb }

  condition:
    any of them
}