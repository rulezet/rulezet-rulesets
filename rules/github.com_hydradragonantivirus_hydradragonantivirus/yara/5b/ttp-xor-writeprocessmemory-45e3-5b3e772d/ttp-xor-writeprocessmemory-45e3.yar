rule TTP_XOR_WriteProcessMemory_45e3 {
  strings:
    $key_45e3 = { 12 91 [2] 20 b3 [2] 26 86 [2] 08 86 [2] 37 9a }

  condition:
    any of them
}