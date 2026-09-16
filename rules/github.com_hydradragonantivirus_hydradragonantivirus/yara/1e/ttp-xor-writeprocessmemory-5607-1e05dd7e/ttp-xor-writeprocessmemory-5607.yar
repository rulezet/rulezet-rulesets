rule TTP_XOR_WriteProcessMemory_5607 {
  strings:
    $key_5607 = { 01 75 [2] 33 57 [2] 35 62 [2] 1b 62 [2] 24 7e }

  condition:
    any of them
}