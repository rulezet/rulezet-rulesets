rule TTP_XOR_WriteProcessMemory_5177 {
  strings:
    $key_5177 = { 06 05 [2] 34 27 [2] 32 12 [2] 1c 12 [2] 23 0e }

  condition:
    any of them
}