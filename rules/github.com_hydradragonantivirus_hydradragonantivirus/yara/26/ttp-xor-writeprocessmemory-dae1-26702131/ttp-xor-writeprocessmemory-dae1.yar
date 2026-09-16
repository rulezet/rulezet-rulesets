rule TTP_XOR_WriteProcessMemory_dae1 {
  strings:
    $key_dae1 = { 8d 93 [2] bf b1 [2] b9 84 [2] 97 84 [2] a8 98 }

  condition:
    any of them
}