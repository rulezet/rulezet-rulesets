rule TTP_XOR_WriteProcessMemory_0d07 {
  strings:
    $key_0d07 = { 5a 75 [2] 68 57 [2] 6e 62 [2] 40 62 [2] 7f 7e }

  condition:
    any of them
}