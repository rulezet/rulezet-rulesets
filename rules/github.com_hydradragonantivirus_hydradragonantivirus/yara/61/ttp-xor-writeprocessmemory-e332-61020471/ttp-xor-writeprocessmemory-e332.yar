rule TTP_XOR_WriteProcessMemory_e332 {
  strings:
    $key_e332 = { b4 40 [2] 86 62 [2] 80 57 [2] ae 57 [2] 91 4b }

  condition:
    any of them
}