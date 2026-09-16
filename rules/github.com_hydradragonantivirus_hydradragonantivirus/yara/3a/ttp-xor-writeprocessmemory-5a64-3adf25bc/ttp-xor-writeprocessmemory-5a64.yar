rule TTP_XOR_WriteProcessMemory_5a64 {
  strings:
    $key_5a64 = { 0d 16 [2] 3f 34 [2] 39 01 [2] 17 01 [2] 28 1d }

  condition:
    any of them
}