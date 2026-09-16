rule TTP_XOR_WriteProcessMemory_4507 {
  strings:
    $key_4507 = { 12 75 [2] 20 57 [2] 26 62 [2] 08 62 [2] 37 7e }

  condition:
    any of them
}