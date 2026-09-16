rule TTP_XOR_WriteProcessMemory_4e07 {
  strings:
    $key_4e07 = { 19 75 [2] 2b 57 [2] 2d 62 [2] 03 62 [2] 3c 7e }

  condition:
    any of them
}