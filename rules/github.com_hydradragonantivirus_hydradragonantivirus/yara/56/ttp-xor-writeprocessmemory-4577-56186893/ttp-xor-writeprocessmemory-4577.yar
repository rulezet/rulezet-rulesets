rule TTP_XOR_WriteProcessMemory_4577 {
  strings:
    $key_4577 = { 12 05 [2] 20 27 [2] 26 12 [2] 08 12 [2] 37 0e }

  condition:
    any of them
}