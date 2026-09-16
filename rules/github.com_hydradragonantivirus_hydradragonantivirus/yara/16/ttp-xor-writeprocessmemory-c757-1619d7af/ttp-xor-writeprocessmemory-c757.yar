rule TTP_XOR_WriteProcessMemory_c757 {
  strings:
    $key_c757 = { 90 25 [2] a2 07 [2] a4 32 [2] 8a 32 [2] b5 2e }

  condition:
    any of them
}