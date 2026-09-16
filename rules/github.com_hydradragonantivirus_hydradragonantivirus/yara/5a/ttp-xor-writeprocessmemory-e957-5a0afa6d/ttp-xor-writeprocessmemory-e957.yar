rule TTP_XOR_WriteProcessMemory_e957 {
  strings:
    $key_e957 = { be 25 [2] 8c 07 [2] 8a 32 [2] a4 32 [2] 9b 2e }

  condition:
    any of them
}