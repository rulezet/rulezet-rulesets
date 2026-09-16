rule TTP_XOR_WriteProcessMemory_3407 {
  strings:
    $key_3407 = { 63 75 [2] 51 57 [2] 57 62 [2] 79 62 [2] 46 7e }

  condition:
    any of them
}