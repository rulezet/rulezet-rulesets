rule TTP_XOR_WriteProcessMemory_d657 {
  strings:
    $key_d657 = { 81 25 [2] b3 07 [2] b5 32 [2] 9b 32 [2] a4 2e }

  condition:
    any of them
}