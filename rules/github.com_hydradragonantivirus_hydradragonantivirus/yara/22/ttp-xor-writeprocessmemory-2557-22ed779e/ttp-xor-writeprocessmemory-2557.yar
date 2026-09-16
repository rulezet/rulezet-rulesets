rule TTP_XOR_WriteProcessMemory_2557 {
  strings:
    $key_2557 = { 72 25 [2] 40 07 [2] 46 32 [2] 68 32 [2] 57 2e }

  condition:
    any of them
}