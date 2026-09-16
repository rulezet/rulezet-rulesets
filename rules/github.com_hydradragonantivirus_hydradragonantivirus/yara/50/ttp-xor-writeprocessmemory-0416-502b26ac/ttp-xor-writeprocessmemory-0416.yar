rule TTP_XOR_WriteProcessMemory_0416 {
  strings:
    $key_0416 = { 53 64 [2] 61 46 [2] 67 73 [2] 49 73 [2] 76 6f }

  condition:
    any of them
}