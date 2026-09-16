rule TTP_XOR_WriteProcessMemory_6257 {
  strings:
    $key_6257 = { 35 25 [2] 07 07 [2] 01 32 [2] 2f 32 [2] 10 2e }

  condition:
    any of them
}