rule TTP_XOR_WriteProcessMemory_4143 {
  strings:
    $key_4143 = { 16 31 [2] 24 13 [2] 22 26 [2] 0c 26 [2] 33 3a }

  condition:
    any of them
}