rule TTP_XOR_WriteProcessMemory_c253 {
  strings:
    $key_c253 = { 95 21 [2] a7 03 [2] a1 36 [2] 8f 36 [2] b0 2a }

  condition:
    any of them
}