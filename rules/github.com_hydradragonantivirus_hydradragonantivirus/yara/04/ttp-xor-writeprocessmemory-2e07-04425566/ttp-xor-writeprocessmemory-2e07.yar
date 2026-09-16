rule TTP_XOR_WriteProcessMemory_2e07 {
  strings:
    $key_2e07 = { 79 75 [2] 4b 57 [2] 4d 62 [2] 63 62 [2] 5c 7e }

  condition:
    any of them
}