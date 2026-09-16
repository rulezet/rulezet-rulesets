rule TTP_XOR_WriteProcessMemory_d443 {
  strings:
    $key_d443 = { 83 31 [2] b1 13 [2] b7 26 [2] 99 26 [2] a6 3a }

  condition:
    any of them
}