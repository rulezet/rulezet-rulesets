rule TTP_XOR_WriteProcessMemory_7e07 {
  strings:
    $key_7e07 = { 29 75 [2] 1b 57 [2] 1d 62 [2] 33 62 [2] 0c 7e }

  condition:
    any of them
}