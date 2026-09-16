rule TTP_XOR_WriteProcessMemory_4207 {
  strings:
    $key_4207 = { 15 75 [2] 27 57 [2] 21 62 [2] 0f 62 [2] 30 7e }

  condition:
    any of them
}