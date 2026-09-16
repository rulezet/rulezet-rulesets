rule TTP_XOR_WriteProcessMemory_c232 {
  strings:
    $key_c232 = { 95 40 [2] a7 62 [2] a1 57 [2] 8f 57 [2] b0 4b }

  condition:
    any of them
}