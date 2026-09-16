rule TTP_XOR_WriteProcessMemory_4543 {
  strings:
    $key_4543 = { 12 31 [2] 20 13 [2] 26 26 [2] 08 26 [2] 37 3a }

  condition:
    any of them
}