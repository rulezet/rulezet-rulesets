rule TTP_XOR_WriteProcessMemory_c503 {
  strings:
    $key_c503 = { 92 71 [2] a0 53 [2] a6 66 [2] 88 66 [2] b7 7a }

  condition:
    any of them
}