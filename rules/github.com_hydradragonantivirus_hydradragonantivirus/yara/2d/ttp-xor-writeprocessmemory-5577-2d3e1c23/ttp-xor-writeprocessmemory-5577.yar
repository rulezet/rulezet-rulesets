rule TTP_XOR_WriteProcessMemory_5577 {
  strings:
    $key_5577 = { 02 05 [2] 30 27 [2] 36 12 [2] 18 12 [2] 27 0e }

  condition:
    any of them
}