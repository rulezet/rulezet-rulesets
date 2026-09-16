rule TTP_XOR_WriteProcessMemory_e302 {
  strings:
    $key_e302 = { b4 70 [2] 86 52 [2] 80 67 [2] ae 67 [2] 91 7b }

  condition:
    any of them
}