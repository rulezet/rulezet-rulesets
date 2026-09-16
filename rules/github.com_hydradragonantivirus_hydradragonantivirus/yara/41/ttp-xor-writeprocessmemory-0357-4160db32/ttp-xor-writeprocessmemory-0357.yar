rule TTP_XOR_WriteProcessMemory_0357 {
  strings:
    $key_0357 = { 54 25 [2] 66 07 [2] 60 32 [2] 4e 32 [2] 71 2e }

  condition:
    any of them
}