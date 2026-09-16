rule TTP_XOR_WriteProcessMemory_5464 {
  strings:
    $key_5464 = { 03 16 [2] 31 34 [2] 37 01 [2] 19 01 [2] 26 1d }

  condition:
    any of them
}