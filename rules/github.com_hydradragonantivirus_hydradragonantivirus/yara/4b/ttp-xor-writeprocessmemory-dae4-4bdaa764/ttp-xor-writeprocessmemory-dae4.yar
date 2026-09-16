rule TTP_XOR_WriteProcessMemory_dae4 {
  strings:
    $key_dae4 = { 8d 96 [2] bf b4 [2] b9 81 [2] 97 81 [2] a8 9d }

  condition:
    any of them
}