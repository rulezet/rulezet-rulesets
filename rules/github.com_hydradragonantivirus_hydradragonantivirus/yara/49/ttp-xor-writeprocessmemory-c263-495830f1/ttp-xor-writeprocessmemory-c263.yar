rule TTP_XOR_WriteProcessMemory_c263 {
  strings:
    $key_c263 = { 95 11 [2] a7 33 [2] a1 06 [2] 8f 06 [2] b0 1a }

  condition:
    any of them
}