rule TTP_XOR_WriteProcessMemory_63f4 {
  strings:
    $key_63f4 = { 34 86 [2] 06 a4 [2] 00 91 [2] 2e 91 [2] 11 8d }

  condition:
    any of them
}