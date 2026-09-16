rule TTP_XOR_WriteProcessMemory_7f07 {
  strings:
    $key_7f07 = { 28 75 [2] 1a 57 [2] 1c 62 [2] 32 62 [2] 0d 7e }

  condition:
    any of them
}