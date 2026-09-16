rule TTP_XOR_WriteProcessMemory_14d7 {
  strings:
    $key_14d7 = { 43 a5 [2] 71 87 [2] 77 b2 [2] 59 b2 [2] 66 ae }

  condition:
    any of them
}