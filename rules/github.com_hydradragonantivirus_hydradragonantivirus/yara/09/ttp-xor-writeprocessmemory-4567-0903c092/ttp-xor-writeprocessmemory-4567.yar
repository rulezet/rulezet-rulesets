rule TTP_XOR_WriteProcessMemory_4567 {
  strings:
    $key_4567 = { 12 15 [2] 20 37 [2] 26 02 [2] 08 02 [2] 37 1e }

  condition:
    any of them
}