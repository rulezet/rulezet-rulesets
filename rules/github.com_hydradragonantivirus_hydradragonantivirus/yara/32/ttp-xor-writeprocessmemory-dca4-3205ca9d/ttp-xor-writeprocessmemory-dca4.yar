rule TTP_XOR_WriteProcessMemory_dca4 {
  strings:
    $key_dca4 = { 8b d6 [2] b9 f4 [2] bf c1 [2] 91 c1 [2] ae dd }

  condition:
    any of them
}