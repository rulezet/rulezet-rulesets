rule TTP_XOR_WriteProcessMemory_0657 {
  strings:
    $key_0657 = { 51 25 [2] 63 07 [2] 65 32 [2] 4b 32 [2] 74 2e }

  condition:
    any of them
}