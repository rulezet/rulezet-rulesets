rule TTP_XOR_WriteProcessMemory_d466 {
  strings:
    $key_d466 = { 83 14 [2] b1 36 [2] b7 03 [2] 99 03 [2] a6 1f }

  condition:
    any of them
}