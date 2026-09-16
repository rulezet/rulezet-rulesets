rule TTP_XOR_WriteProcessMemory_a757 {
  strings:
    $key_a757 = { f0 25 [2] c2 07 [2] c4 32 [2] ea 32 [2] d5 2e }

  condition:
    any of them
}