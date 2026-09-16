rule TTP_XOR_WriteProcessMemory_5147 {
  strings:
    $key_5147 = { 06 35 [2] 34 17 [2] 32 22 [2] 1c 22 [2] 23 3e }

  condition:
    any of them
}