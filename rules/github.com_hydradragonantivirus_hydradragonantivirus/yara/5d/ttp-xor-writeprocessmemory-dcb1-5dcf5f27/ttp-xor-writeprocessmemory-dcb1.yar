rule TTP_XOR_WriteProcessMemory_dcb1 {
  strings:
    $key_dcb1 = { 8b c3 [2] b9 e1 [2] bf d4 [2] 91 d4 [2] ae c8 }

  condition:
    any of them
}