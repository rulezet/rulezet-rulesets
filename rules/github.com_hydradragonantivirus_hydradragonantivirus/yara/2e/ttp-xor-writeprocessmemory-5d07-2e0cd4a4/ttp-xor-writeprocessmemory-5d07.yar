rule TTP_XOR_WriteProcessMemory_5d07 {
  strings:
    $key_5d07 = { 0a 75 [2] 38 57 [2] 3e 62 [2] 10 62 [2] 2f 7e }

  condition:
    any of them
}