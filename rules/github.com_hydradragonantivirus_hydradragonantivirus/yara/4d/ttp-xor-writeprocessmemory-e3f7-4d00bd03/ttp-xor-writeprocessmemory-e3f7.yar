rule TTP_XOR_WriteProcessMemory_e3f7 {
  strings:
    $key_e3f7 = { b4 85 [2] 86 a7 [2] 80 92 [2] ae 92 [2] 91 8e }

  condition:
    any of them
}