rule TTP_XOR_WriteProcessMemory_0157 {
  strings:
    $key_0157 = { 56 25 [2] 64 07 [2] 62 32 [2] 4c 32 [2] 73 2e }

  condition:
    any of them
}