rule TTP_XOR_WriteProcessMemory_e677 {
  strings:
    $key_e677 = { b1 05 [2] 83 27 [2] 85 12 [2] ab 12 [2] 94 0e }

  condition:
    any of them
}