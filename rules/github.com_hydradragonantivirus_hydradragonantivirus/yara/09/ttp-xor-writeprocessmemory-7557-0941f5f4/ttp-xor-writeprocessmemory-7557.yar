rule TTP_XOR_WriteProcessMemory_7557 {
  strings:
    $key_7557 = { 22 25 [2] 10 07 [2] 16 32 [2] 38 32 [2] 07 2e }

  condition:
    any of them
}