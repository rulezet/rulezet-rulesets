rule TTP_XOR_WriteProcessMemory_7567 {
  strings:
    $key_7567 = { 22 15 [2] 10 37 [2] 16 02 [2] 38 02 [2] 07 1e }

  condition:
    any of them
}