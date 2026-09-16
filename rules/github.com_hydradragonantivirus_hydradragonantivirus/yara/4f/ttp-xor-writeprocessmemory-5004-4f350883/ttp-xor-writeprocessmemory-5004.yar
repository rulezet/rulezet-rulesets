rule TTP_XOR_WriteProcessMemory_5004 {
  strings:
    $key_5004 = { 07 76 [2] 35 54 [2] 33 61 [2] 1d 61 [2] 22 7d }

  condition:
    any of them
}