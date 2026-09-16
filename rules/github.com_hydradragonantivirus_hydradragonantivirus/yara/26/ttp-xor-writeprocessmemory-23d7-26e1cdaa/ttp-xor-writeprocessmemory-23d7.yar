rule TTP_XOR_WriteProcessMemory_23d7 {
  strings:
    $key_23d7 = { 74 a5 [2] 46 87 [2] 40 b2 [2] 6e b2 [2] 51 ae }

  condition:
    any of them
}