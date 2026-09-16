rule TTP_XOR_WriteProcessMemory_6d17 {
  strings:
    $key_6d17 = { 3a 65 [2] 08 47 [2] 0e 72 [2] 20 72 [2] 1f 6e }

  condition:
    any of them
}