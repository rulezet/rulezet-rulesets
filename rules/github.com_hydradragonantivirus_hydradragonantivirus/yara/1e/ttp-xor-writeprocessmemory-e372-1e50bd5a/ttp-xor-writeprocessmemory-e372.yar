rule TTP_XOR_WriteProcessMemory_e372 {
  strings:
    $key_e372 = { b4 00 [2] 86 22 [2] 80 17 [2] ae 17 [2] 91 0b }

  condition:
    any of them
}