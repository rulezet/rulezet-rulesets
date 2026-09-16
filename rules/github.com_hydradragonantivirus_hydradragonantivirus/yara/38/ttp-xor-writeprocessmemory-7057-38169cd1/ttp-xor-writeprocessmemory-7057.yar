rule TTP_XOR_WriteProcessMemory_7057 {
  strings:
    $key_7057 = { 27 25 [2] 15 07 [2] 13 32 [2] 3d 32 [2] 02 2e }

  condition:
    any of them
}