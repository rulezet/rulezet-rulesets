rule TTP_XOR_WriteProcessMemory_bd57 {
  strings:
    $key_bd57 = { ea 25 [2] d8 07 [2] de 32 [2] f0 32 [2] cf 2e }

  condition:
    any of them
}