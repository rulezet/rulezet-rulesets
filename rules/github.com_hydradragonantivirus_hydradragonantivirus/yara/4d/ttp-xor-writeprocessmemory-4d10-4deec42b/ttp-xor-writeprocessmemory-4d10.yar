rule TTP_XOR_WriteProcessMemory_4d10 {
  strings:
    $key_4d10 = { 1a 62 [2] 28 40 [2] 2e 75 [2] 00 75 [2] 3f 69 }

  condition:
    any of them
}