rule TTP_XOR_WriteProcessMemory_7364 {
  strings:
    $key_7364 = { 24 16 [2] 16 34 [2] 10 01 [2] 3e 01 [2] 01 1d }

  condition:
    any of them
}