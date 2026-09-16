rule TTP_XOR_WriteProcessMemory_e374 {
  strings:
    $key_e374 = { b4 06 [2] 86 24 [2] 80 11 [2] ae 11 [2] 91 0d }

  condition:
    any of them
}