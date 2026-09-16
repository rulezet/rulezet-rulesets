rule TTP_XOR_WriteProcessMemory_e033 {
  strings:
    $key_e033 = { b7 41 [2] 85 63 [2] 83 56 [2] ad 56 [2] 92 4a }

  condition:
    any of them
}