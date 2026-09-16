rule TTP_XOR_WriteProcessMemory_5354 {
  strings:
    $key_5354 = { 04 26 [2] 36 04 [2] 30 31 [2] 1e 31 [2] 21 2d }

  condition:
    any of them
}