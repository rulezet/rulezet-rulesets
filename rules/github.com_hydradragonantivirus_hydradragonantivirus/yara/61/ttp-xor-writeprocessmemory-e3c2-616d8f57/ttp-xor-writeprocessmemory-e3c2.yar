rule TTP_XOR_WriteProcessMemory_e3c2 {
  strings:
    $key_e3c2 = { b4 b0 [2] 86 92 [2] 80 a7 [2] ae a7 [2] 91 bb }

  condition:
    any of them
}