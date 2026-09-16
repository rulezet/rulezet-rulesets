rule TTP_XOR_WriteProcessMemory_0e57 {
  strings:
    $key_0e57 = { 59 25 [2] 6b 07 [2] 6d 32 [2] 43 32 [2] 7c 2e }

  condition:
    any of them
}