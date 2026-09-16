rule TTP_XOR_WriteProcessMemory_4d74 {
  strings:
    $key_4d74 = { 1a 06 [2] 28 24 [2] 2e 11 [2] 00 11 [2] 3f 0d }

  condition:
    any of them
}