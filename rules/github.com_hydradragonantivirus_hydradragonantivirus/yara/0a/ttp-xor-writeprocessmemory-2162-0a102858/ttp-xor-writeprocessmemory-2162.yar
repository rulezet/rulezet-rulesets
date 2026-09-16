rule TTP_XOR_WriteProcessMemory_2162 {
  strings:
    $key_2162 = { 76 10 [2] 44 32 [2] 42 07 [2] 6c 07 [2] 53 1b }

  condition:
    any of them
}