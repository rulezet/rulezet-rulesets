rule TTP_XOR_WriteProcessMemory_6374 {
  strings:
    $key_6374 = { 34 06 [2] 06 24 [2] 00 11 [2] 2e 11 [2] 11 0d }

  condition:
    any of them
}