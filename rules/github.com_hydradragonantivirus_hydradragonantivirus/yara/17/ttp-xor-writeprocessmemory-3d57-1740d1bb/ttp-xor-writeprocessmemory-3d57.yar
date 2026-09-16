rule TTP_XOR_WriteProcessMemory_3d57 {
  strings:
    $key_3d57 = { 6a 25 [2] 58 07 [2] 5e 32 [2] 70 32 [2] 4f 2e }

  condition:
    any of them
}