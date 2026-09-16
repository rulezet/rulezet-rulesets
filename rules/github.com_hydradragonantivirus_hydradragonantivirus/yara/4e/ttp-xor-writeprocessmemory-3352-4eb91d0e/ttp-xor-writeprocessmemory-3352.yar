rule TTP_XOR_WriteProcessMemory_3352 {
  strings:
    $key_3352 = { 64 20 [2] 56 02 [2] 50 37 [2] 7e 37 [2] 41 2b }

  condition:
    any of them
}