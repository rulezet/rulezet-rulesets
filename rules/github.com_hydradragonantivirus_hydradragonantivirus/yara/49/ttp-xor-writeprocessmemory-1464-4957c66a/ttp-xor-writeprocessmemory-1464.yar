rule TTP_XOR_WriteProcessMemory_1464 {
  strings:
    $key_1464 = { 43 16 [2] 71 34 [2] 77 01 [2] 59 01 [2] 66 1d }

  condition:
    any of them
}