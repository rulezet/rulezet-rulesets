rule TTP_XOR_WriteProcessMemory_e343 {
  strings:
    $key_e343 = { b4 31 [2] 86 13 [2] 80 26 [2] ae 26 [2] 91 3a }

  condition:
    any of them
}