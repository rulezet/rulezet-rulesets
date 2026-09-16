rule TTP_XOR_WriteProcessMemory_5067 {
  strings:
    $key_5067 = { 07 15 [2] 35 37 [2] 33 02 [2] 1d 02 [2] 22 1e }

  condition:
    any of them
}