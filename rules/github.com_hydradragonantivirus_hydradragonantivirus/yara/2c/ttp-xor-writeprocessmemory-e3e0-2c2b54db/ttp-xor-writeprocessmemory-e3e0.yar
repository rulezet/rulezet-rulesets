rule TTP_XOR_WriteProcessMemory_e3e0 {
  strings:
    $key_e3e0 = { b4 92 [2] 86 b0 [2] 80 85 [2] ae 85 [2] 91 99 }

  condition:
    any of them
}