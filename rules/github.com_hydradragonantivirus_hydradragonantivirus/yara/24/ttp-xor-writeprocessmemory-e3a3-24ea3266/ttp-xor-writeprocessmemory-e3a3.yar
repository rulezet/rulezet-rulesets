rule TTP_XOR_WriteProcessMemory_e3a3 {
  strings:
    $key_e3a3 = { b4 d1 [2] 86 f3 [2] 80 c6 [2] ae c6 [2] 91 da }

  condition:
    any of them
}