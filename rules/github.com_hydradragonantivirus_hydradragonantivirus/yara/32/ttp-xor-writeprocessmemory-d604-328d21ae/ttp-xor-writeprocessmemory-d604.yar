rule TTP_XOR_WriteProcessMemory_d604 {
  strings:
    $key_d604 = { 81 76 [2] b3 54 [2] b5 61 [2] 9b 61 [2] a4 7d }

  condition:
    any of them
}