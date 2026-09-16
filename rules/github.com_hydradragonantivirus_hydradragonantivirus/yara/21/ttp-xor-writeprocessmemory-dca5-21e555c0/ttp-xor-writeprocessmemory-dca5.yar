rule TTP_XOR_WriteProcessMemory_dca5 {
  strings:
    $key_dca5 = { 8b d7 [2] b9 f5 [2] bf c0 [2] 91 c0 [2] ae dc }

  condition:
    any of them
}