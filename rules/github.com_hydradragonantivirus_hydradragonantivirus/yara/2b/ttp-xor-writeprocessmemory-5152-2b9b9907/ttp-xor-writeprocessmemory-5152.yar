rule TTP_XOR_WriteProcessMemory_5152 {
  strings:
    $key_5152 = { 06 20 [2] 34 02 [2] 32 37 [2] 1c 37 [2] 23 2b }

  condition:
    any of them
}