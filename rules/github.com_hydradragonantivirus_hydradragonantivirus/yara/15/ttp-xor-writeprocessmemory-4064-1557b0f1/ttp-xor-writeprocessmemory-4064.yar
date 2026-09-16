rule TTP_XOR_WriteProcessMemory_4064 {
  strings:
    $key_4064 = { 17 16 [2] 25 34 [2] 23 01 [2] 0d 01 [2] 32 1d }

  condition:
    any of them
}