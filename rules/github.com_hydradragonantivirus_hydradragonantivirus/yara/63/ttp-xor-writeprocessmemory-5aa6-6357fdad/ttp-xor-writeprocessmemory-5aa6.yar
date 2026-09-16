rule TTP_XOR_WriteProcessMemory_5aa6 {
  strings:
    $key_5aa6 = { 0d d4 [2] 3f f6 [2] 39 c3 [2] 17 c3 [2] 28 df }

  condition:
    any of them
}