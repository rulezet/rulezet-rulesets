rule TTP_XOR_WriteProcessMemory_e007 {
  strings:
    $key_e007 = { b7 75 [2] 85 57 [2] 83 62 [2] ad 62 [2] 92 7e }

  condition:
    any of them
}