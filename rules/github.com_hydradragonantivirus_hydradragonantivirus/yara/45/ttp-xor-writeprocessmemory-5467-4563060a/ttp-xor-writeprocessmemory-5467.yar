rule TTP_XOR_WriteProcessMemory_5467 {
  strings:
    $key_5467 = { 03 15 [2] 31 37 [2] 37 02 [2] 19 02 [2] 26 1e }

  condition:
    any of them
}