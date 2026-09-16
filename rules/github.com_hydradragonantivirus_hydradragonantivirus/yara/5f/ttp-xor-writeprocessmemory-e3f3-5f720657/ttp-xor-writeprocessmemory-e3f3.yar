rule TTP_XOR_WriteProcessMemory_e3f3 {
  strings:
    $key_e3f3 = { b4 81 [2] 86 a3 [2] 80 96 [2] ae 96 [2] 91 8a }

  condition:
    any of them
}