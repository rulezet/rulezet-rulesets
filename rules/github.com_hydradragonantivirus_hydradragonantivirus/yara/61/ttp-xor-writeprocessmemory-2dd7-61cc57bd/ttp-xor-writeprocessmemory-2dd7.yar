rule TTP_XOR_WriteProcessMemory_2dd7 {
  strings:
    $key_2dd7 = { 7a a5 [2] 48 87 [2] 4e b2 [2] 60 b2 [2] 5f ae }

  condition:
    any of them
}