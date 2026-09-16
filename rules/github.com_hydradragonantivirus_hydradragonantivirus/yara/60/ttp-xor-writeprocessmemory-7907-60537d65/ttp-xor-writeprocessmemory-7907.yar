rule TTP_XOR_WriteProcessMemory_7907 {
  strings:
    $key_7907 = { 2e 75 [2] 1c 57 [2] 1a 62 [2] 34 62 [2] 0b 7e }

  condition:
    any of them
}