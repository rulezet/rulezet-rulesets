rule TTP_XOR_WriteProcessMemory_d1e4 {
  strings:
    $key_d1e4 = { 86 96 [2] b4 b4 [2] b2 81 [2] 9c 81 [2] a3 9d }

  condition:
    any of them
}