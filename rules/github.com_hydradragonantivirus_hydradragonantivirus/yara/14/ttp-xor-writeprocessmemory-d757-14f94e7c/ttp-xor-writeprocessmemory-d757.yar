rule TTP_XOR_WriteProcessMemory_d757 {
  strings:
    $key_d757 = { 80 25 [2] b2 07 [2] b4 32 [2] 9a 32 [2] a5 2e }

  condition:
    any of them
}