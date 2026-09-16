rule TTP_XOR_WriteProcessMemory_ec64 {
  strings:
    $key_ec64 = { bb 16 [2] 89 34 [2] 8f 01 [2] a1 01 [2] 9e 1d }

  condition:
    any of them
}