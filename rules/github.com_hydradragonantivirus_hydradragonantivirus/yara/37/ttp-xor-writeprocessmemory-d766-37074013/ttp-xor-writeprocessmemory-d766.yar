rule TTP_XOR_WriteProcessMemory_d766 {
  strings:
    $key_d766 = { 80 14 [2] b2 36 [2] b4 03 [2] 9a 03 [2] a5 1f }

  condition:
    any of them
}