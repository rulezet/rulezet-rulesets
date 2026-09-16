rule TTP_XOR_WriteProcessMemory_d157 {
  strings:
    $key_d157 = { 86 25 [2] b4 07 [2] b2 32 [2] 9c 32 [2] a3 2e }

  condition:
    any of them
}