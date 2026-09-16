rule TTP_XOR_WriteProcessMemory_5034 {
  strings:
    $key_5034 = { 07 46 [2] 35 64 [2] 33 51 [2] 1d 51 [2] 22 4d }

  condition:
    any of them
}