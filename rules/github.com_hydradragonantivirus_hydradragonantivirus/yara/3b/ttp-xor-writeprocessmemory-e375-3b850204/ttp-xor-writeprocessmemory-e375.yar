rule TTP_XOR_WriteProcessMemory_e375 {
  strings:
    $key_e375 = { b4 07 [2] 86 25 [2] 80 10 [2] ae 10 [2] 91 0c }

  condition:
    any of them
}