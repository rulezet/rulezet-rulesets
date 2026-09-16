rule TTP_XOR_WriteProcessMemory_e3f0 {
  strings:
    $key_e3f0 = { b4 82 [2] 86 a0 [2] 80 95 [2] ae 95 [2] 91 89 }

  condition:
    any of them
}