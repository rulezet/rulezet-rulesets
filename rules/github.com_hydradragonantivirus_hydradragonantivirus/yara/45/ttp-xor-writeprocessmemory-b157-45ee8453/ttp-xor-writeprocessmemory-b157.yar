rule TTP_XOR_WriteProcessMemory_b157 {
  strings:
    $key_b157 = { e6 25 [2] d4 07 [2] d2 32 [2] fc 32 [2] c3 2e }

  condition:
    any of them
}