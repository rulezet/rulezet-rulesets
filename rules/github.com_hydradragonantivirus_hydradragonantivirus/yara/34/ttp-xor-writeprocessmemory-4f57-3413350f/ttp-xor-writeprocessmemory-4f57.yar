rule TTP_XOR_WriteProcessMemory_4f57 {
  strings:
    $key_4f57 = { 18 25 [2] 2a 07 [2] 2c 32 [2] 02 32 [2] 3d 2e }

  condition:
    any of them
}