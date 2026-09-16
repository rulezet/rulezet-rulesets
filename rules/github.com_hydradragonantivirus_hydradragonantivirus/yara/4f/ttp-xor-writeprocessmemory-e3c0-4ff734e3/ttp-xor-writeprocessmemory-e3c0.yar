rule TTP_XOR_WriteProcessMemory_e3c0 {
  strings:
    $key_e3c0 = { b4 b2 [2] 86 90 [2] 80 a5 [2] ae a5 [2] 91 b9 }

  condition:
    any of them
}