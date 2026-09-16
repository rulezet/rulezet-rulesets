rule TTP_XOR_WriteProcessMemory_1d53 {
  strings:
    $key_1d53 = { 4a 21 [2] 78 03 [2] 7e 36 [2] 50 36 [2] 6f 2a }

  condition:
    any of them
}