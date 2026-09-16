rule TTP_XOR_WriteProcessMemory_3607 {
  strings:
    $key_3607 = { 61 75 [2] 53 57 [2] 55 62 [2] 7b 62 [2] 44 7e }

  condition:
    any of them
}