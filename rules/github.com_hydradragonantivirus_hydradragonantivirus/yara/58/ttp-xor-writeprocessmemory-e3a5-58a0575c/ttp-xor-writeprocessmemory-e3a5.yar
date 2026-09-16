rule TTP_XOR_WriteProcessMemory_e3a5 {
  strings:
    $key_e3a5 = { b4 d7 [2] 86 f5 [2] 80 c0 [2] ae c0 [2] 91 dc }

  condition:
    any of them
}