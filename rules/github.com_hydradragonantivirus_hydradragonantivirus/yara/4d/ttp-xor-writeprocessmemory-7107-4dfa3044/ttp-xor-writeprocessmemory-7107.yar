rule TTP_XOR_WriteProcessMemory_7107 {
  strings:
    $key_7107 = { 26 75 [2] 14 57 [2] 12 62 [2] 3c 62 [2] 03 7e }

  condition:
    any of them
}