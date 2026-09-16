rule TTP_XOR_WriteProcessMemory_e022 {
  strings:
    $key_e022 = { b7 50 [2] 85 72 [2] 83 47 [2] ad 47 [2] 92 5b }

  condition:
    any of them
}