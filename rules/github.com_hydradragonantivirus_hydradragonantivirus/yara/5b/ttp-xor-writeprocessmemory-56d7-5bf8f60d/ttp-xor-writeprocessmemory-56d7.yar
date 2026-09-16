rule TTP_XOR_WriteProcessMemory_56d7 {
  strings:
    $key_56d7 = { 01 a5 [2] 33 87 [2] 35 b2 [2] 1b b2 [2] 24 ae }

  condition:
    any of them
}