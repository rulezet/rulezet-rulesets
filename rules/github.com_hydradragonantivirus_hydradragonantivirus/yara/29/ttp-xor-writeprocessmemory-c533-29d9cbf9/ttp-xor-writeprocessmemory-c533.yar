rule TTP_XOR_WriteProcessMemory_c533 {
  strings:
    $key_c533 = { 92 41 [2] a0 63 [2] a6 56 [2] 88 56 [2] b7 4a }

  condition:
    any of them
}