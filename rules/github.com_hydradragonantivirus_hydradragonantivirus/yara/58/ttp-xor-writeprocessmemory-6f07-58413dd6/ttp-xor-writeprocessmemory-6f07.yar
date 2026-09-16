rule TTP_XOR_WriteProcessMemory_6f07 {
  strings:
    $key_6f07 = { 38 75 [2] 0a 57 [2] 0c 62 [2] 22 62 [2] 1d 7e }

  condition:
    any of them
}