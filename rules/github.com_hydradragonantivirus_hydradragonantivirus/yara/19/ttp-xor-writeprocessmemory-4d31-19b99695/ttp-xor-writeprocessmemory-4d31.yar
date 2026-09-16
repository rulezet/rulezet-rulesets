rule TTP_XOR_WriteProcessMemory_4d31 {
  strings:
    $key_4d31 = { 1a 43 [2] 28 61 [2] 2e 54 [2] 00 54 [2] 3f 48 }

  condition:
    any of them
}