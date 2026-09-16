rule TTP_XOR_WriteProcessMemory_4252 {
  strings:
    $key_4252 = { 15 20 [2] 27 02 [2] 21 37 [2] 0f 37 [2] 30 2b }

  condition:
    any of them
}