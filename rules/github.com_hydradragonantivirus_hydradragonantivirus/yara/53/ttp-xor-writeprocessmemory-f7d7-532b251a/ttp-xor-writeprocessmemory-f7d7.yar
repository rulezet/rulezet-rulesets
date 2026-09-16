rule TTP_XOR_WriteProcessMemory_f7d7 {
  strings:
    $key_f7d7 = { a0 a5 [2] 92 87 [2] 94 b2 [2] ba b2 [2] 85 ae }

  condition:
    any of them
}