rule TTP_XOR_WriteProcessMemory_ec57 {
  strings:
    $key_ec57 = { bb 25 [2] 89 07 [2] 8f 32 [2] a1 32 [2] 9e 2e }

  condition:
    any of them
}