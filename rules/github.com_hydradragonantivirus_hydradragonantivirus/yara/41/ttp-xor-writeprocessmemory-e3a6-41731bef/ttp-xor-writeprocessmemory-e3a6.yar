rule TTP_XOR_WriteProcessMemory_e3a6 {
  strings:
    $key_e3a6 = { b4 d4 [2] 86 f6 [2] 80 c3 [2] ae c3 [2] 91 df }

  condition:
    any of them
}