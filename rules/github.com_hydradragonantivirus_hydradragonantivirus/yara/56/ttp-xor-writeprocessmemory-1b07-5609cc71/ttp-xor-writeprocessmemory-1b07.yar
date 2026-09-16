rule TTP_XOR_WriteProcessMemory_1b07 {
  strings:
    $key_1b07 = { 4c 75 [2] 7e 57 [2] 78 62 [2] 56 62 [2] 69 7e }

  condition:
    any of them
}