rule TTP_XOR_WriteProcessMemory_7867 {
  strings:
    $key_7867 = { 2f 15 [2] 1d 37 [2] 1b 02 [2] 35 02 [2] 0a 1e }

  condition:
    any of them
}