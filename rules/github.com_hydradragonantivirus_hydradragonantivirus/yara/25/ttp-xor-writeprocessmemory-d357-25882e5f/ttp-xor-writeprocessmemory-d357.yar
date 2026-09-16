rule TTP_XOR_WriteProcessMemory_d357 {
  strings:
    $key_d357 = { 84 25 [2] b6 07 [2] b0 32 [2] 9e 32 [2] a1 2e }

  condition:
    any of them
}