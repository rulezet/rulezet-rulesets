rule TTP_XOR_WriteProcessMemory_1d52 {
  strings:
    $key_1d52 = { 4a 20 [2] 78 02 [2] 7e 37 [2] 50 37 [2] 6f 2b }

  condition:
    any of them
}