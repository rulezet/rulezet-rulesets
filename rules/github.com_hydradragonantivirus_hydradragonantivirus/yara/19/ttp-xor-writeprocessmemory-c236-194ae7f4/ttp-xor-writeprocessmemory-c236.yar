rule TTP_XOR_WriteProcessMemory_c236 {
  strings:
    $key_c236 = { 95 44 [2] a7 66 [2] a1 53 [2] 8f 53 [2] b0 4f }

  condition:
    any of them
}