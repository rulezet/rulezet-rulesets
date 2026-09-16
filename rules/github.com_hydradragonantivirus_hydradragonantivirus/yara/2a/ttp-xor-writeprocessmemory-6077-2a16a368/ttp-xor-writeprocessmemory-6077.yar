rule TTP_XOR_WriteProcessMemory_6077 {
  strings:
    $key_6077 = { 37 05 [2] 05 27 [2] 03 12 [2] 2d 12 [2] 12 0e }

  condition:
    any of them
}