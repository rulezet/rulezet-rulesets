rule TTP_XOR_WriteProcessMemory_4243 {
  strings:
    $key_4243 = { 15 31 [2] 27 13 [2] 21 26 [2] 0f 26 [2] 30 3a }

  condition:
    any of them
}