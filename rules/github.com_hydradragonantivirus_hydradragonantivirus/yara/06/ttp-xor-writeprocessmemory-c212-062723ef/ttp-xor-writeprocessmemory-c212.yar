rule TTP_XOR_WriteProcessMemory_c212 {
  strings:
    $key_c212 = { 95 60 [2] a7 42 [2] a1 77 [2] 8f 77 [2] b0 6b }

  condition:
    any of them
}