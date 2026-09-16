rule TTP_XOR_WriteProcessMemory_e3a8 {
  strings:
    $key_e3a8 = { b4 da [2] 86 f8 [2] 80 cd [2] ae cd [2] 91 d1 }

  condition:
    any of them
}