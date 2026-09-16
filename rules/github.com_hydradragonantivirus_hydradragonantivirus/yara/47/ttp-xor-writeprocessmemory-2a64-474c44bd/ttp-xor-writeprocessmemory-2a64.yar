rule TTP_XOR_WriteProcessMemory_2a64 {
  strings:
    $key_2a64 = { 7d 16 [2] 4f 34 [2] 49 01 [2] 67 01 [2] 58 1d }

  condition:
    any of them
}