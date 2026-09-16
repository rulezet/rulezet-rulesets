rule TTP_XOR_WriteProcessMemory_5bd7 {
  strings:
    $key_5bd7 = { 0c a5 [2] 3e 87 [2] 38 b2 [2] 16 b2 [2] 29 ae }

  condition:
    any of them
}