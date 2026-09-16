rule TTP_XOR_WriteProcessMemory_0bd7 {
  strings:
    $key_0bd7 = { 5c a5 [2] 6e 87 [2] 68 b2 [2] 46 b2 [2] 79 ae }

  condition:
    any of them
}