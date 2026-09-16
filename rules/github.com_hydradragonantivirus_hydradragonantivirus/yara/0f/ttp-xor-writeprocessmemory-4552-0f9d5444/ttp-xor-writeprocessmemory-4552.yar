rule TTP_XOR_WriteProcessMemory_4552 {
  strings:
    $key_4552 = { 12 20 [2] 20 02 [2] 26 37 [2] 08 37 [2] 37 2b }

  condition:
    any of them
}