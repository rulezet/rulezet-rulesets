rule TTP_XOR_WriteProcessMemory_2257 {
  strings:
    $key_2257 = { 75 25 [2] 47 07 [2] 41 32 [2] 6f 32 [2] 50 2e }

  condition:
    any of them
}