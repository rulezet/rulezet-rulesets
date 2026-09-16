rule TTP_XOR_WriteProcessMemory_37e3 {
  strings:
    $key_37e3 = { 60 91 [2] 52 b3 [2] 54 86 [2] 7a 86 [2] 45 9a }

  condition:
    any of them
}