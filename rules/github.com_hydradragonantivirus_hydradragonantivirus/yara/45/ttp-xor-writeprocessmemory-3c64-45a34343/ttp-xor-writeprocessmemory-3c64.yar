rule TTP_XOR_WriteProcessMemory_3c64 {
  strings:
    $key_3c64 = { 6b 16 [2] 59 34 [2] 5f 01 [2] 71 01 [2] 4e 1d }

  condition:
    any of them
}