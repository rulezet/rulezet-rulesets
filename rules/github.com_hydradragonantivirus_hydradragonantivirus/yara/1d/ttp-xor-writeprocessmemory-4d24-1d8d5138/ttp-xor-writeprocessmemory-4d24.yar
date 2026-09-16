rule TTP_XOR_WriteProcessMemory_4d24 {
  strings:
    $key_4d24 = { 1a 56 [2] 28 74 [2] 2e 41 [2] 00 41 [2] 3f 5d }

  condition:
    any of them
}