rule TTP_XOR_WriteProcessMemory_3d62 {
  strings:
    $key_3d62 = { 6a 10 [2] 58 32 [2] 5e 07 [2] 70 07 [2] 4f 1b }

  condition:
    any of them
}