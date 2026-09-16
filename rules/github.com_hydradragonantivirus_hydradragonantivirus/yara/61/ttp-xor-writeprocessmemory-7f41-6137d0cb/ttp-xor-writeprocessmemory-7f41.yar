rule TTP_XOR_WriteProcessMemory_7f41 {
  strings:
    $key_7f41 = { 28 33 [2] 1a 11 [2] 1c 24 [2] 32 24 [2] 0d 38 }

  condition:
    any of them
}