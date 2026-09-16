rule TTP_XOR_WriteProcessMemory_4557 {
  strings:
    $key_4557 = { 12 25 [2] 20 07 [2] 26 32 [2] 08 32 [2] 37 2e }

  condition:
    any of them
}