rule TTP_XOR_WriteProcessMemory_77f4 {
  strings:
    $key_77f4 = { 20 86 [2] 12 a4 [2] 14 91 [2] 3a 91 [2] 05 8d }

  condition:
    any of them
}