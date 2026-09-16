rule TTP_XOR_WriteProcessMemory_5917 {
  strings:
    $key_5917 = { 0e 65 [2] 3c 47 [2] 3a 72 [2] 14 72 [2] 2b 6e }

  condition:
    any of them
}