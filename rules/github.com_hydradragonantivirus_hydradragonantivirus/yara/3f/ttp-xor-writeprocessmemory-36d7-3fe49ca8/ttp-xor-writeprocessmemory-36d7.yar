rule TTP_XOR_WriteProcessMemory_36d7 {
  strings:
    $key_36d7 = { 61 a5 [2] 53 87 [2] 55 b2 [2] 7b b2 [2] 44 ae }

  condition:
    any of them
}