rule TTP_XOR_WriteProcessMemory_e457 {
  strings:
    $key_e457 = { b3 25 [2] 81 07 [2] 87 32 [2] a9 32 [2] 96 2e }

  condition:
    any of them
}