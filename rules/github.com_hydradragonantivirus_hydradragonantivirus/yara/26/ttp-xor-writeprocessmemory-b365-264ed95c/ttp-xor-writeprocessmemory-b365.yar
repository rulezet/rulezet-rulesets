rule TTP_XOR_WriteProcessMemory_b365 {
  strings:
    $key_b365 = { e4 17 [2] d6 35 [2] d0 00 [2] fe 00 [2] c1 1c }

  condition:
    any of them
}