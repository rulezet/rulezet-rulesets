rule TTP_XOR_WriteProcessMemory_e307 {
  strings:
    $key_e307 = { b4 75 [2] 86 57 [2] 80 62 [2] ae 62 [2] 91 7e }

  condition:
    any of them
}