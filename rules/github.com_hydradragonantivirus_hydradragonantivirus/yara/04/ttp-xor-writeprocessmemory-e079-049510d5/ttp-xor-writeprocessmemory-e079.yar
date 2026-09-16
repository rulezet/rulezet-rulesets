rule TTP_XOR_WriteProcessMemory_e079 {
  strings:
    $key_e079 = { b7 0b [2] 85 29 [2] 83 1c [2] ad 1c [2] 92 00 }

  condition:
    any of them
}