rule TTP_XOR_WriteProcessMemory_1357 {
  strings:
    $key_1357 = { 44 25 [2] 76 07 [2] 70 32 [2] 5e 32 [2] 61 2e }

  condition:
    any of them
}