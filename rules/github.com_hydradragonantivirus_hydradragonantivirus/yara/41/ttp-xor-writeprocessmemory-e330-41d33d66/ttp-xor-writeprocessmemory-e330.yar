rule TTP_XOR_WriteProcessMemory_e330 {
  strings:
    $key_e330 = { b4 42 [2] 86 60 [2] 80 55 [2] ae 55 [2] 91 49 }

  condition:
    any of them
}