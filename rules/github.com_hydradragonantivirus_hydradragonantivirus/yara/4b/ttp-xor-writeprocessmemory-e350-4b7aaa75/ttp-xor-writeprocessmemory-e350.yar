rule TTP_XOR_WriteProcessMemory_e350 {
  strings:
    $key_e350 = { b4 22 [2] 86 00 [2] 80 35 [2] ae 35 [2] 91 29 }

  condition:
    any of them
}