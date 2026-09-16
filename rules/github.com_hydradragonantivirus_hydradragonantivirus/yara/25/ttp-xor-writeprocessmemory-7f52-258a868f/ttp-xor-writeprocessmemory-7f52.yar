rule TTP_XOR_WriteProcessMemory_7f52 {
  strings:
    $key_7f52 = { 28 20 [2] 1a 02 [2] 1c 37 [2] 32 37 [2] 0d 2b }

  condition:
    any of them
}