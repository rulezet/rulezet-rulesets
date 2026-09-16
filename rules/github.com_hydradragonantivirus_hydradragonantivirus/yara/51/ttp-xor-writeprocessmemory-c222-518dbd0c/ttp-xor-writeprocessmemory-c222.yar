rule TTP_XOR_WriteProcessMemory_c222 {
  strings:
    $key_c222 = { 95 50 [2] a7 72 [2] a1 47 [2] 8f 47 [2] b0 5b }

  condition:
    any of them
}