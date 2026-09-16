rule TTP_XOR_WriteProcessMemory_e962 {
  strings:
    $key_e962 = { be 10 [2] 8c 32 [2] 8a 07 [2] a4 07 [2] 9b 1b }

  condition:
    any of them
}