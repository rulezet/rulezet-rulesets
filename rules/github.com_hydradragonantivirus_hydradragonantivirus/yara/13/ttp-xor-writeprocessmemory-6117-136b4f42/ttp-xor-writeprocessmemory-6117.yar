rule TTP_XOR_WriteProcessMemory_6117 {
  strings:
    $key_6117 = { 36 65 [2] 04 47 [2] 02 72 [2] 2c 72 [2] 13 6e }

  condition:
    any of them
}