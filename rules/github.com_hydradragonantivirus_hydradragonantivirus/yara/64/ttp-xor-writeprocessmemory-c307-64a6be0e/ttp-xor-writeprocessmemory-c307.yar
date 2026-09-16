rule TTP_XOR_WriteProcessMemory_c307 {
  strings:
    $key_c307 = { 94 75 [2] a6 57 [2] a0 62 [2] 8e 62 [2] b1 7e }

  condition:
    any of them
}