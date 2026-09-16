rule TTP_XOR_WriteProcessMemory_7052 {
  strings:
    $key_7052 = { 27 20 [2] 15 02 [2] 13 37 [2] 3d 37 [2] 02 2b }

  condition:
    any of them
}