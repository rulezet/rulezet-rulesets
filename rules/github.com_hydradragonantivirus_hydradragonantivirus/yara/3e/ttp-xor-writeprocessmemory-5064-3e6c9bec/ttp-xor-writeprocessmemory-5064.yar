rule TTP_XOR_WriteProcessMemory_5064 {
  strings:
    $key_5064 = { 07 16 [2] 35 34 [2] 33 01 [2] 1d 01 [2] 22 1d }

  condition:
    any of them
}