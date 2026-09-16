rule TTP_XOR_WriteProcessMemory_77e3 {
  strings:
    $key_77e3 = { 20 91 [2] 12 b3 [2] 14 86 [2] 3a 86 [2] 05 9a }

  condition:
    any of them
}