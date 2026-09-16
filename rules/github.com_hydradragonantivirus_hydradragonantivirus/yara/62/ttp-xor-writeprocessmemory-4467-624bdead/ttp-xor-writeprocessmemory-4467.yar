rule TTP_XOR_WriteProcessMemory_4467 {
  strings:
    $key_4467 = { 13 15 [2] 21 37 [2] 27 02 [2] 09 02 [2] 36 1e }

  condition:
    any of them
}