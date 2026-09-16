rule TTP_XOR_WriteProcessMemory_4d03 {
  strings:
    $key_4d03 = { 1a 71 [2] 28 53 [2] 2e 66 [2] 00 66 [2] 3f 7a }

  condition:
    any of them
}