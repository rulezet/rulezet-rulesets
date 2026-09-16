rule TTP_XOR_WriteProcessMemory_e3a7 {
  strings:
    $key_e3a7 = { b4 d5 [2] 86 f7 [2] 80 c2 [2] ae c2 [2] 91 de }

  condition:
    any of them
}