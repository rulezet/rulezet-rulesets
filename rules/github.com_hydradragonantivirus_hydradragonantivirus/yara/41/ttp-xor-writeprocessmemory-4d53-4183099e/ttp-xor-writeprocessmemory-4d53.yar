rule TTP_XOR_WriteProcessMemory_4d53 {
  strings:
    $key_4d53 = { 1a 21 [2] 28 03 [2] 2e 36 [2] 00 36 [2] 3f 2a }

  condition:
    any of them
}