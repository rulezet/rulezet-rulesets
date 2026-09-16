rule TTP_XOR_WriteProcessMemory_5d67 {
  strings:
    $key_5d67 = { 0a 15 [2] 38 37 [2] 3e 02 [2] 10 02 [2] 2f 1e }

  condition:
    any of them
}