rule TTP_XOR_WriteProcessMemory_44e3 {
  strings:
    $key_44e3 = { 13 91 [2] 21 b3 [2] 27 86 [2] 09 86 [2] 36 9a }

  condition:
    any of them
}