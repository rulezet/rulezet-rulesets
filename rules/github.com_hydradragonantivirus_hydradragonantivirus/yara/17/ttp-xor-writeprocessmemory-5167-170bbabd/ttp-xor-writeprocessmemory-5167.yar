rule TTP_XOR_WriteProcessMemory_5167 {
  strings:
    $key_5167 = { 06 15 [2] 34 37 [2] 32 02 [2] 1c 02 [2] 23 1e }

  condition:
    any of them
}