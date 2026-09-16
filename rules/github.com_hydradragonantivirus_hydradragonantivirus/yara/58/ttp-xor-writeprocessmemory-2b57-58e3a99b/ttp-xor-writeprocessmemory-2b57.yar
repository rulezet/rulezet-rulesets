rule TTP_XOR_WriteProcessMemory_2b57 {
  strings:
    $key_2b57 = { 7c 25 [2] 4e 07 [2] 48 32 [2] 66 32 [2] 59 2e }

  condition:
    any of them
}