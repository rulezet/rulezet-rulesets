rule TTP_XOR_WriteProcessMemory_e065 {
  strings:
    $key_e065 = { b7 17 [2] 85 35 [2] 83 00 [2] ad 00 [2] 92 1c }

  condition:
    any of them
}