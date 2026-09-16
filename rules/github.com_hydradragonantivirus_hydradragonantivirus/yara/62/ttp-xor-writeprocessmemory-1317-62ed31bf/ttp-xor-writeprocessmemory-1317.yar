rule TTP_XOR_WriteProcessMemory_1317 {
  strings:
    $key_1317 = { 44 65 [2] 76 47 [2] 70 72 [2] 5e 72 [2] 61 6e }

  condition:
    any of them
}