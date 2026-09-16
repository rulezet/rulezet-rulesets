rule TTP_XOR_WriteProcessMemory_dae7 {
  strings:
    $key_dae7 = { 8d 95 [2] bf b7 [2] b9 82 [2] 97 82 [2] a8 9e }

  condition:
    any of them
}