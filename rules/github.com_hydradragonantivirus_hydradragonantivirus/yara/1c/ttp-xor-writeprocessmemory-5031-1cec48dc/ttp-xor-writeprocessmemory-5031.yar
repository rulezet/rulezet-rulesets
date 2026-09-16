rule TTP_XOR_WriteProcessMemory_5031 {
  strings:
    $key_5031 = { 07 43 [2] 35 61 [2] 33 54 [2] 1d 54 [2] 22 48 }

  condition:
    any of them
}