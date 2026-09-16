rule TTP_XOR_WriteProcessMemory_dca0 {
  strings:
    $key_dca0 = { 8b d2 [2] b9 f0 [2] bf c5 [2] 91 c5 [2] ae d9 }

  condition:
    any of them
}