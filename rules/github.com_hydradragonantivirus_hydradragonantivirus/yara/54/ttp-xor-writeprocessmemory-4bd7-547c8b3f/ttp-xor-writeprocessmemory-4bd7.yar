rule TTP_XOR_WriteProcessMemory_4bd7 {
  strings:
    $key_4bd7 = { 1c a5 [2] 2e 87 [2] 28 b2 [2] 06 b2 [2] 39 ae }

  condition:
    any of them
}