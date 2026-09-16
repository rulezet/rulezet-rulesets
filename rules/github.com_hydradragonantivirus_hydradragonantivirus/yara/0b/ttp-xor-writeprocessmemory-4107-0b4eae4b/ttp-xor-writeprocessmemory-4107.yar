rule TTP_XOR_WriteProcessMemory_4107 {
  strings:
    $key_4107 = { 16 75 [2] 24 57 [2] 22 62 [2] 0c 62 [2] 33 7e }

  condition:
    any of them
}