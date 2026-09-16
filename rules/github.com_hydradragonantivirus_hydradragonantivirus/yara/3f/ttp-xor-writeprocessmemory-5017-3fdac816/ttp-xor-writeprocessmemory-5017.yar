rule TTP_XOR_WriteProcessMemory_5017 {
  strings:
    $key_5017 = { 07 65 [2] 35 47 [2] 33 72 [2] 1d 72 [2] 22 6e }

  condition:
    any of them
}