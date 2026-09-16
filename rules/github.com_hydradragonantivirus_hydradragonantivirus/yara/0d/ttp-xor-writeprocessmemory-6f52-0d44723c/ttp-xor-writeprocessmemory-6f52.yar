rule TTP_XOR_WriteProcessMemory_6f52 {
  strings:
    $key_6f52 = { 38 20 [2] 0a 02 [2] 0c 37 [2] 22 37 [2] 1d 2b }

  condition:
    any of them
}