rule TTP_XOR_WriteProcessMemory_3706 {
  strings:
    $key_3706 = { 60 74 [2] 52 56 [2] 54 63 [2] 7a 63 [2] 45 7f }

  condition:
    any of them
}