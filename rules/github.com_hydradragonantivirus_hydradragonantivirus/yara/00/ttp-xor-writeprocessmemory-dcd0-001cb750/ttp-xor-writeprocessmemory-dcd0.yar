rule TTP_XOR_WriteProcessMemory_dcd0 {
  strings:
    $key_dcd0 = { 8b a2 [2] b9 80 [2] bf b5 [2] 91 b5 [2] ae a9 }

  condition:
    any of them
}