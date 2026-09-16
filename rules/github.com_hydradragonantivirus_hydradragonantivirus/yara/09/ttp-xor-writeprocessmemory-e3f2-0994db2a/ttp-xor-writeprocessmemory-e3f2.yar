rule TTP_XOR_WriteProcessMemory_e3f2 {
  strings:
    $key_e3f2 = { b4 80 [2] 86 a2 [2] 80 97 [2] ae 97 [2] 91 8b }

  condition:
    any of them
}