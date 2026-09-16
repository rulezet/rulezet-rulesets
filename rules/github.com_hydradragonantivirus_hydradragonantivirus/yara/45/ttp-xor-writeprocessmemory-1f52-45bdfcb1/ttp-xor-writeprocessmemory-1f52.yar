rule TTP_XOR_WriteProcessMemory_1f52 {
  strings:
    $key_1f52 = { 48 20 [2] 7a 02 [2] 7c 37 [2] 52 37 [2] 6d 2b }

  condition:
    any of them
}