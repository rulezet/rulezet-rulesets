rule TTP_XOR_WriteProcessMemory_dae2 {
  strings:
    $key_dae2 = { 8d 90 [2] bf b2 [2] b9 87 [2] 97 87 [2] a8 9b }

  condition:
    any of them
}