rule TTP_XOR_WriteProcessMemory_4aa6 {
  strings:
    $key_4aa6 = { 1d d4 [2] 2f f6 [2] 29 c3 [2] 07 c3 [2] 38 df }

  condition:
    any of them
}